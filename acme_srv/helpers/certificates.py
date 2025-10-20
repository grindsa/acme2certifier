# -*- coding: utf-8 -*-
"""Certificate utilities for acme2certifier"""
import base64
import logging
from typing import List, Tuple
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import load_pem_x509_certificate, ocsp
from OpenSSL import crypto
from .encoding import convert_string_to_byte, convert_byte_to_string, build_pem_file, b64_url_recode, b64_decode
from .datetime_utils import date_to_uts_utc

def cert_aki_get(logger: logging.Logger, certificate: str) -> str:
    """get subject key identifier from certificate"""
    logger.debug("Helper.cert_ski_get()")

    cert = cert_load(logger, certificate, recode=True)
    try:
        aki = cert.extensions.get_extension_for_oid(x509.OID_AUTHORITY_KEY_IDENTIFIER)
        aki_value = aki.value.key_identifier.hex()
    except Exception as _err:
        aki_value = cert_aki_pyopenssl_get(logger, certificate)
    logger.debug("cert_aki_get() ended with: %s", aki_value)
    return aki_value



def cert_aki_pyopenssl_get(logger, certificate: str) -> str:
    """Get Authority Key Identifier from a certificate as a hex string."""
    logger.debug("Helper.cert_aki_pyopenssl_cert()")

    pem_data = convert_string_to_byte(
        build_pem_file(logger, None, b64_url_recode(logger, certificate), True)
    )
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_data)
    # Get the AKI extension
    aki = None
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        if "authorityKeyIdentifier" in str(ext.get_short_name()):
            aki = ext
    if aki:
        # Get the SKI value and convert it to hex
        aki_hex = aki.get_data()[4:].hex()
    else:
        logger.warning("No AKI found in certificate")
        aki_hex = None
    logger.debug("Helper.cert_ski_pyopenssl_cert() ended with: %s", aki_hex)
    return aki_hex



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



def cert_san_pyopenssl_get(logger, certificate, recode=True):
    """get subject alternate names from certificate"""
    logger.debug("Helper.cert_san_pyopenssl_get()")
    if recode:
        pem_file = build_pem_file(
            logger, None, b64_url_recode(logger, certificate), True
        )
    else:
        pem_file = certificate

    cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_file)
    san = []
    ext_count = cert.get_extension_count()
    for i in range(0, ext_count):
        ext = cert.get_extension(i)
        if "subjectAltName" in str(ext.get_short_name()):
            # pylint: disable=c2801
            san_list = ext.__str__().split(",")
            for san_name in san_list:
                san_name = san_name.rstrip()
                san_name = san_name.lstrip()
                san.append(san_name)

    logger.debug("Helper.cert_san_pyopenssl_get() ended")
    return san



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
    except Exception as err:
        logger.error("Error while getting SANs from certificate: %s", err)
        # we may add the routing to get the sanes via pyopenssl here if needed (sans = cert_san_pyopenssl_get(logger, certificate, recode=recode))

    logger.debug("Helper.cert_san_get() ended")
    return sans



def cert_ski_pyopenssl_get(logger, certificate: str) -> str:
    """Get Subject Key Identifier from a certificate as a hex string."""
    logger.debug("Helper.cert_ski_pyopenssl_cert()")

    pem_data = convert_string_to_byte(
        build_pem_file(logger, None, b64_url_recode(logger, certificate), True)
    )
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_data)
    # Get the SKI extension
    ski = None
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        if "subjectKeyIdentifier" in str(ext.get_short_name()):
            ski = ext
    if ski:
        # Get the SKI value and convert it to hex
        ski_hex = ski.get_data()[2:].hex()
    else:
        logger.warning("No SKI found in certificate")
        ski_hex = None
    logger.debug("Helper.cert_ski_pyopenssl_cert() ended with: %s", ski_hex)
    return ski_hex



def cert_ski_get(logger: logging.Logger, certificate: str) -> str:
    """get subject key identifier from certificate"""
    logger.debug("Helper.cert_ski_get()")

    cert = cert_load(logger, certificate, recode=True)
    try:
        ski = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_KEY_IDENTIFIER)
        ski_value = ski.value.digest.hex()
    except Exception as err:
        logger.error("Error while getting the SKI fallback to Openssl method: %s", err)
        ski_value = cert_ski_pyopenssl_get(logger, certificate)
    logger.debug("Helper.cert_ski_get() ended with: %s", ski_value)
    return ski_value



def cryptography_version_get(logger: logging.Logger) -> int:
    """get version number of cryptography module"""
    logger.debug("Helper.cryptography_version_get()")
    # pylint: disable=c0415
    import cryptography

    try:
        version_list = cryptography.__version__.split(".")
        if version_list:
            major_version = int(version_list[0])
    except Exception as err:
        logger.error(
            "Error while getting the version number of the cryptography module: %s", err
        )
        major_version = 36

    logger.debug("cryptography_version_get() ended with %s", major_version)
    return major_version



def cert_extensions_get(logger: logging.Logger, certificate: str, recode: bool = True):
    """get extenstions from certificate certificate"""
    logger.debug("Helper.cert_extensions_get()")

    crypto_module_version = cryptography_version_get(logger)
    if crypto_module_version < 36:
        logger.debug("Helper.cert_extensions_get(): using pyopenssl")
        extension_list = cert_extensions_py_openssl_get(logger, certificate, recode)
    else:
        cert = cert_load(logger, certificate, recode=recode)
        extension_list = []
        for extension in cert.extensions:
            extension_list.append(
                convert_byte_to_string(base64.b64encode(extension.value.public_bytes()))
            )

    logger.debug("Helper.cert_extensions_get() ended with: %s", extension_list)
    return extension_list



def cert_extensions_py_openssl_get(logger, certificate, recode=True):
    """get extenstions from certificate certificate"""
    logger.debug("cert_extensions_py_openssl_get()")
    if recode:
        pem_file = build_pem_file(
            logger, None, b64_url_recode(logger, certificate), True
        )
    else:
        pem_file = certificate

    cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_file)
    extension_list = []
    ext_count = cert.get_extension_count()
    for i in range(0, ext_count):
        ext = cert.get_extension(i)
        extension_list.append(convert_byte_to_string(base64.b64encode(ext.get_data())))

    logger.debug("cert_extensions_py_openssl_get() ended with: %s", extension_list)
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



