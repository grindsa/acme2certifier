# -*- coding: utf-8 -*-
"""Certificate utilities for acme2certifier"""

import base64
import logging
from typing import List, Tuple, Optional, Set
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization.pkcs7 import (
    load_pem_pkcs7_certificates,
    load_der_pkcs7_certificates,
)
from cryptography.x509 import load_pem_x509_certificate, ocsp
from .encoding import (
    convert_string_to_byte,
    convert_byte_to_string,
    build_pem_file,
    b64_url_recode,
    b64_decode,
)
from .datetime_utils import date_to_uts_utc
from pyasn1.codec.der import decoder
from pyasn1.type import univ
from pyasn1_modules import rfc5280

_OID_SKI = "2.5.29.14"
_OID_AKI = "2.5.29.35"


def _cert_pem_to_der(logger: logging.Logger, certificate: str) -> bytes:
    """Convert certificate input to DER bytes without parsing extensions."""
    pem_data = convert_string_to_byte(
        build_pem_file(logger, None, b64_url_recode(logger, certificate), True)
    )
    # Prefer cryptography load for PEM framing only; public_bytes touches extensions
    # on some versions, so strip PEM manually.
    lines = convert_byte_to_string(pem_data).strip().splitlines()
    b64 = "".join(line for line in lines if not line.startswith("-----"))
    return base64.b64decode(b64)


def _cert_extension_raw_get(
    logger: logging.Logger, certificate: str, oid: str
) -> Optional[bytes]:
    """Return extnValue (OCTET STRING contents) for oid, or None."""
    logger.debug("_cert_extension_raw_get(%s)", oid)
    der = _cert_pem_to_der(logger, certificate)
    cert_asn1, _ = decoder.decode(der, asn1Spec=rfc5280.Certificate())
    extensions = cert_asn1["tbsCertificate"]["extensions"]
    if extensions is None or not extensions.hasValue():
        return None
    for ext in extensions:
        if str(ext["extnID"]) == oid:
            return bytes(ext["extnValue"])
    return None


def _cert_aki_asn1_get(logger: logging.Logger, certificate: str) -> Optional[str]:
    """Get AKI keyIdentifier as hex via ASN.1 (tolerates illegal BasicConstraints)."""
    logger.debug("_cert_aki_asn1_get()")
    extn_value = _cert_extension_raw_get(logger, certificate, _OID_AKI)
    if not extn_value:
        logger.warning("No AKI found in certificate")
        return None
    aki, _ = decoder.decode(extn_value, asn1Spec=rfc5280.AuthorityKeyIdentifier())
    if not aki["keyIdentifier"].isValue:
        logger.warning("AKI extension present but keyIdentifier missing")
        return None
    aki_hex = bytes(aki["keyIdentifier"]).hex()
    logger.debug("_cert_aki_asn1_get() ended with: %s", aki_hex)
    return aki_hex


def cert_aki_get(logger: logging.Logger, certificate: str) -> str:
    """get subject key identifier from certificate"""
    logger.debug("Helper.cert_ski_get()")

    cert = cert_load(logger, certificate, recode=True)
    try:
        aki = cert.extensions.get_extension_for_oid(x509.OID_AUTHORITY_KEY_IDENTIFIER)
        aki_value = aki.value.key_identifier.hex()
    except Exception as _err:
        logger.error(
            "Error while getting AKI from certificate: %s. Fallback to ASN.1 method",
            _err,
        )
        aki_value = _cert_aki_asn1_get(logger, certificate)

    logger.debug("cert_aki_get() ended with: %s", aki_value)
    return aki_value


def _cert_ski_asn1_get(logger: logging.Logger, certificate: str) -> Optional[str]:
    """Get SKI as hex via ASN.1 (tolerates illegal BasicConstraints)."""
    logger.debug("_cert_ski_asn1_get()")
    extn_value = _cert_extension_raw_get(logger, certificate, _OID_SKI)
    if not extn_value:
        logger.warning("No SKI found in certificate")
        return None
    ski, _ = decoder.decode(extn_value, asn1Spec=univ.OctetString())
    ski_hex = bytes(ski).hex()
    logger.debug("_cert_ski_asn1_get() ended with: %s", ski_hex)
    return ski_hex


def cert_load(
    logger: logging.Logger, certificate: str, recode: bool
) -> x509.Certificate:
    """load certificate object from pem _Format"""
    logger.debug("Helper.cert_load(%s)", recode)

    if recode:
        pem_data = convert_string_to_byte(
            build_pem_file(logger, None, b64_url_recode(logger, certificate), True)
        )
    else:
        pem_data = convert_string_to_byte(certificate)
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())

    return cert


def cert_dates_get(logger: logging.Logger, certificate: str) -> Tuple[int, int]:
    """get date number form certificate"""
    logger.debug("Helper.cert_dates_get()")

    issue_date = 0
    expiration_date = 0
    try:
        cert = cert_load(logger, certificate, recode=True)
        issue_date = date_to_uts_utc(
            cert.not_valid_before_utc, _tformat="%Y-%m-%d %H:%M:%S"
        )
        expiration_date = date_to_uts_utc(
            cert.not_valid_after_utc, _tformat="%Y-%m-%d %H:%M:%S"
        )
    except Exception as err:
        logger.debug(
            "Error while getting dates from certificate. Fallback to deprecated method: %s",
            err,
        )
        try:
            issue_date = date_to_uts_utc(
                cert.not_valid_before, _tformat="%Y-%m-%d %H:%M:%S"
            )
            expiration_date = date_to_uts_utc(
                cert.not_valid_after, _tformat="%Y-%m-%d %H:%M:%S"
            )
        except Exception:
            logger.error("Error while getting dates from certificate: %s", err)
            issue_date = 0
            expiration_date = 0

    logger.debug("cert_dates_get() ended with: %s/%s", issue_date, expiration_date)
    return (issue_date, expiration_date)


def cert_cn_get(logger: logging.Logger, certificate: str) -> str:
    """get cn from certificate"""
    logger.debug("Helper.cert_cn_get()")

    cert = cert_load(logger, certificate, recode=True)
    # get subject and look for common name
    subject = cert.subject
    result = None
    for attr in subject:
        if attr.oid == x509.NameOID.COMMON_NAME:
            result = attr.value
            break
    logger.debug("Helper.cert_cn_get() ended with: %s", result)
    return result


def cert_der2pem(der_cert: bytes) -> str:
    """convert certificate der to pem"""
    cert = x509.load_der_x509_certificate(der_cert)
    pem_cert = cert.public_bytes(serialization.Encoding.PEM)
    return pem_cert


def cert_issuer_get(logger: logging.Logger, certificate: str) -> str:
    """get certificate issuer from certificate"""
    logger.debug("Helper.cert_issuer_get()")

    cert = cert_load(logger, certificate, recode=True)
    result = cert.issuer.rfc4514_string()
    logger.debug("Helper.cert_issuer_get() ended with: %s", result)
    return result


def cert_pem2der(pem_cert: str) -> bytes:
    """convert certificate pem to der"""
    cert = x509.load_pem_x509_certificate(pem_cert.encode(), default_backend())
    der_cert = cert.public_bytes(serialization.Encoding.DER)
    return der_cert


def cert_pubkey_get(logger: logging.Logger, certificate=str) -> str:
    """get public key from certificate"""
    logger.debug("Helper.cert_pubkey_get()")
    cert = cert_load(logger, certificate, recode=False)
    public_key = cert.public_key()
    pubkey_str = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    logger.debug("Helper.cert_pubkey_get() ended with: %s", pubkey_str)
    return convert_byte_to_string(pubkey_str)


def cert_san_get(
    logger: logging.Logger, certificate: str, recode: bool = True
) -> List[str]:
    """get subject alternate names from certificate"""
    logger.debug("Helper.cert_san_get(%s)", recode)

    cert = cert_load(logger, certificate, recode=recode)
    sans = []
    try:
        ext = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
        sans_list = ext.value.get_values_for_type(x509.DNSName)
        for san in sans_list:
            sans.append(f"DNS:{san}")
        sans_list = ext.value.get_values_for_type(x509.IPAddress)
        for san in sans_list:
            sans.append(f"IP:{san}")
        sans_list = ext.value.get_values_for_type(x509.RFC822Name)
        for san in sans_list:
            sans.append(f"EMAIL:{san}")
    except Exception as err:
        logger.error("Error while getting SANs from certificate: %s", err)

    logger.debug("Helper.cert_san_get() ended")
    return sans


def cert_bound_names_get(
    logger: logging.Logger,
    certificate: str,
    recode: bool = True,
    email_identifier_rewrite: bool = False,
) -> Set[Tuple[str, str]]:
    """Return normalized (type, value) pairs from certificate SANs and subject CN."""
    from .csr import _cn_bound_type, _normalize_bound_name

    logger.debug(
        "Helper.cert_bound_names_get(email_identifier_rewrite=%s)",
        email_identifier_rewrite,
    )
    names: Set[Tuple[str, str]] = set()
    if not certificate:
        logger.debug("Helper.cert_bound_names_get() ended with: %s", names)
        return names

    for san in cert_san_get(logger, certificate, recode=recode):
        try:
            san_type, san_value = san.split(":", 1)
        except ValueError as err:
            logger.error("Error while splitting SAN %s: %s", san, err)
            continue
        normalized = _normalize_bound_name(
            san_type, san_value, email_identifier_rewrite=email_identifier_rewrite
        )
        if normalized:
            names.add(normalized)

    cn = cert_cn_get(logger, certificate)
    if cn:
        normalized = _normalize_bound_name(
            _cn_bound_type(cn),
            cn,
            email_identifier_rewrite=email_identifier_rewrite,
        )
        if normalized:
            names.add(normalized)

    logger.debug("Helper.cert_bound_names_get() ended with: %s", names)
    return names


def cert_ski_get(logger: logging.Logger, certificate: str) -> str:
    """get subject key identifier from certificate"""
    logger.debug("Helper.cert_ski_get()")

    cert = cert_load(logger, certificate, recode=True)
    try:
        ski = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_KEY_IDENTIFIER)
        ski_value = ski.value.digest.hex()
    except Exception as err:
        logger.error("Error while getting the SKI: %s. Fallback to ASN.1 method", err)
        ski_value = _cert_ski_asn1_get(logger, certificate)

    logger.debug("Helper.cert_ski_get() ended with: %s", ski_value)
    return ski_value


def cert_extensions_get(logger: logging.Logger, certificate: str, recode: bool = True):
    """get extenstions from certificate certificate"""
    logger.debug("Helper.cert_extensions_get()")

    cert = cert_load(logger, certificate, recode=recode)
    extension_list = []
    for extension in cert.extensions:
        extension_list.append(
            convert_byte_to_string(base64.b64encode(extension.value.public_bytes()))
        )

    logger.debug("Helper.cert_extensions_get() ended with: %s", extension_list)
    return extension_list


def cert_serial_get(logger: logging.Logger, certificate: str, hexformat: bool = False):
    """get serial number form certificate"""
    logger.debug("Helper.cert_serial_get()")
    cert = cert_load(logger, certificate, recode=True)
    if hexformat:
        serial_number = f"{cert.serial_number:x}"
        # add leading zero if needed
        serial_number = serial_number.zfill(len(serial_number) + len(serial_number) % 2)
    else:
        serial_number = cert.serial_number
    logger.debug("Helper.cert_serial_get() ended with: %s", serial_number)
    return serial_number


def pembundle_to_list(logger: logging.Logger, pem_bundle: str) -> List[str]:
    """split pem bundle into a list of certificates"""
    logger.debug("Helper.pembundle_to_list()")
    cert_list = []
    pem_data = ""
    if "-----BEGIN CERTIFICATE-----" in pem_bundle:
        for line in pem_bundle.splitlines():
            line = line.strip()
            if line.startswith("-----BEGIN CERTIFICATE-----") and pem_data:
                cert_list.append(pem_data)
                pem_data = ""
            pem_data += line + "\n"
        if pem_data:
            cert_list.append(pem_data)
    logger.debug("Helper.pembundle_to_list() returned %s certificates", cert_list)
    return cert_list


def certid_asn1_get(logger: logging.Logger, cert_pem: str, issuer_pem: str) -> str:
    """get renewal information from certificate"""
    logger.debug("Helper.certid_asn1_get()")

    cert = load_pem_x509_certificate(convert_string_to_byte(cert_pem))
    issuer = load_pem_x509_certificate(convert_string_to_byte(issuer_pem))

    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer, hashes.SHA256())
    ocsprequest = builder.build()
    ocsprequest_hex = ocsprequest.public_bytes(serialization.Encoding.DER).hex()

    # this is ugly but i did not find a better way to do this
    _header, certid_hex = ocsprequest_hex.split("0420", 1)

    return certid_hex


def certid_hex_get(logger: logging.Logger, renewal_info: str) -> Tuple[str, str]:
    """get certid in hex from renewal_info field"""
    logger.debug("Helper.certid_hex_get()")

    renewal_info_b64 = b64_url_recode(logger, renewal_info)
    renewal_info_hex = b64_decode(logger, renewal_info_b64).hex()

    # this is ugly but i did not find a better way to do this
    mda, certid_renewal = renewal_info_hex.split("0420", 1)
    mda = mda[4:]

    logger.debug("Helper.certid_hex_get() endet with %s", certid_renewal)
    return mda, certid_renewal


def certid_check(
    logger: logging.Logger, renewal_info: str, certid_database: str
) -> str:
    """compare certid with renewal info"""
    logger.debug("Helper.certid_check()")

    renewal_info_b64 = b64_url_recode(logger, renewal_info)
    renewal_info_hex = b64_decode(logger, renewal_info_b64).hex()

    # this is ugly but i did not find a better way to do this
    _header, certid_renewal = renewal_info_hex.split("0420", 1)
    result = certid_renewal == certid_database

    logger.debug("Helper.certid_check() ended with: %s", result)
    return result


def pkcs7_to_pem(logger, pkcs7_content: str, outform: str = "string") -> List[str]:
    """convert pkcs7 to pem"""
    logger.debug("CAhandler._pkcs7_to_pem()")

    # Define loading strategies in order of preference
    loading_strategies = [
        # Strategy 1: Load as PEM directly
        lambda content: load_pem_pkcs7_certificates(convert_string_to_byte(content)),
        # Strategy 2: Replace CERTIFICATE with PKCS7 tag and load as PEM
        lambda content: load_pem_pkcs7_certificates(
            convert_string_to_byte(content.replace("CERTIFICATE", "PKCS7"))
        ),
        # Strategy 3: Load as DER
        lambda content: load_der_pkcs7_certificates(content),
    ]

    pkcs7_obj = None
    last_error = None

    for i, strategy in enumerate(loading_strategies):
        try:
            pkcs7_obj = strategy(pkcs7_content)
            if i == 1:  # Log only for the tag replacement strategy
                logger.error("PKCS7-TAG not found, updated content successfully")
            break
        except Exception as err:
            last_error = err
            if i == 0:
                logger.error("PKCS7-TAG not found updating content...")
            elif i == 1:
                logger.debug("CAhandler._pkcs7_to_pem(): load pem failed. Try der...")

    if pkcs7_obj is None:
        logger.error("All PKCS7 loading strategies failed. Last error: %s", last_error)
        raise last_error

    # Convert certificates to PEM format
    cert_pem_list = [
        convert_byte_to_string(cert.public_bytes(serialization.Encoding.PEM))
        for cert in pkcs7_obj
    ]

    # Define output format
    output_formats = {
        "string": lambda certs: "".join(certs),
        "list": lambda certs: certs,
    }

    result = output_formats.get(outform, lambda _: None)(cert_pem_list)

    logger.debug("Certificate._pkcs7_to_pem() ended")
    return result
