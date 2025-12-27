# -*- coding: utf-8 -*-
"""CSR utilities for acme2certifier"""
import base64
import logging
from typing import List, Dict
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from .encoding import (
    convert_string_to_byte,
    convert_byte_to_string,
    build_pem_file,
    b64_url_recode,
    b64_encode,
)


def csr_load(logger: logging.Logger, csr: str) -> x509.CertificateSigningRequest:
    """load certificate object from pem _Format"""
    logger.debug("Helper.cert_load()")

    pem_data = convert_string_to_byte(
        build_pem_file(logger, None, b64_url_recode(logger, csr), True, True)
    )
    csr_data = x509.load_pem_x509_csr(pem_data)

    return csr_data


def csr_cn_get(logger: logging.Logger, csr_pem: str) -> str:
    """get cn from certificate request"""
    logger.debug("Helper.csr_cn_get()")

    csr = csr_load(logger, csr_pem)
    # Extract the subject's common name
    common_name = None
    for attribute in csr.subject:
        if attribute.oid == x509.NameOID.COMMON_NAME:
            common_name = attribute.value
            break

    logger.debug("Helper.csr_cn_get() ended with: %s", common_name)
    return common_name


def csr_dn_get(logger: logging.Logger, csr: str) -> str:
    """get subject from certificate request in openssl notation"""
    logger.debug("Helper.csr_dn_get()")

    csr_obj = csr_load(logger, csr)
    subject = csr_obj.subject.rfc4514_string()

    logger.debug("Helper.csr_dn_get() ended with: %s", subject)
    return subject


def csr_pubkey_get(logger: logging.Logger, csr, encoding="pem"):
    """get public key from certificate request"""
    logger.debug("Helper.csr_pubkey_get()")
    csr_obj = csr_load(logger, csr)
    public_key = csr_obj.public_key()
    if encoding == "pem":
        pubkey_str = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pubkey = convert_byte_to_string(pubkey_str)
    elif encoding == "base64der":
        pubkey_str = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pubkey = b64_encode(logger, pubkey_str)

    elif encoding == "der":
        pubkey = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    else:
        pubkey = None
    logger.debug("Helper.cert_pubkey_get() ended with: %s", pubkey)
    return pubkey


def csr_san_get(logger: logging.Logger, csr: str) -> List[str]:
    """get subject alternate names from certificate"""
    logger.debug("Helper.cert_san_get()")
    sans = []
    if csr:

        csr_obj = csr_load(logger, csr)
        sans = []
        try:
            ext = csr_obj.extensions.get_extension_for_oid(
                x509.OID_SUBJECT_ALTERNATIVE_NAME
            )

            sans_list = ext.value.get_values_for_type(x509.DNSName)
            for san in sans_list:
                sans.append(f"DNS:{san}")
            sans_list = ext.value.get_values_for_type(x509.IPAddress)
            for san in sans_list:
                sans.append(f"IP:{san}")

        except Exception as err:
            logger.error("Error while getting SANs from CSR: %s", err)

    logger.debug("Helper.csr_san_get() ended with: %s", str(sans))
    return sans


def csr_san_byte_get(logger: logging.Logger, csr: str) -> bytes:
    """get sans from CSR as base64 encoded byte squence"""
    # Load the CSR
    logger.debug("Helper.csr_san_byte_get()")

    csr = csr_load(logger, csr)

    # Get the SAN extension
    san_extension = csr.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )

    # Get the SANs
    sans = san_extension.value

    # Serialize the SANs to a byte sequence
    sans_bytes = sans.public_bytes()

    # Encode the byte sequence as base64
    sans_base64 = b64_encode(logger, sans_bytes)

    logger.debug("Helper.csr_san_byte_get() ended")
    return sans_base64


def csr_extensions_get(logger: logging.Logger, csr: str) -> List[str]:
    """get extensions from certificate"""
    logger.debug("Helper.csr_extensions_get()")

    csr_obj = csr_load(logger, csr)

    extension_list = []
    for extension in csr_obj.extensions:
        extension_list.append(
            convert_byte_to_string(base64.b64encode(extension.value.public_bytes()))
        )

    logger.debug("Helper.csr_extensions_get() ended with: %s", extension_list)
    return extension_list


def csr_subject_get(logger: logging.Logger, csr: str) -> Dict[str, str]:
    """get subject from csr as a list of tuples"""
    logger.debug("Helper.csr_subject_get()")
    # pylint: disable=w0212

    csr_obj = csr_load(logger, csr)
    subject_dic = {}
    # get subject and look for common name
    subject = csr_obj.subject
    for attr in subject:
        subject_dic[attr.oid._name] = attr.value

    logger.debug("Helper.csr_subject_get() ended")
    return subject_dic


def csr_cn_lookup(logger: logging.Logger, csr: str) -> str:
    """lookup  CN/ 1st san from CSR"""
    logger.debug("Heloer._csr_cn_lookup()")

    csr_cn = csr_cn_get(logger, csr)
    if not csr_cn:
        # lookup first san
        san_list = csr_san_get(logger, csr)
        if san_list and len(san_list) > 0:
            for san in san_list:
                try:
                    csr_cn = san.split(":")[1]
                    break
                except Exception as err:
                    logger.error("SAN split failed: %s", err)
        else:
            logger.error("No SANs found in CSR")

    logger.debug("Helper._csr_cn_lookup() ended with: %s", csr_cn)
    return csr_cn
