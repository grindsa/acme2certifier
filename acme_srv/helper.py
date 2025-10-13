# pylint: disable=c0302, e0401, r0913
# -*- coding: utf-8 -*-
"""helper functions for acme2certifier"""
from __future__ import print_function
import re
import base64
import json
import random
import calendar
import copy
import configparser
import os
import sys
import importlib
import textwrap
import datetime
from string import digits, ascii_letters
from typing import List, Tuple, Dict
import socket
import ssl
import logging
import hashlib
import html
import ipaddress
from urllib.parse import urlparse, quote
from urllib3.util import connection
import socks
from jwcrypto import jwk, jws
from dateutil.parser import parse
import pytz
import dns.resolver
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import load_pem_x509_certificate, ocsp
from OpenSSL import crypto
import idna
import requests
import requests.packages.urllib3.util.connection as urllib3_cn
from .version import __version__


USER_AGENT = f"acme2certifier/{__version__}"
PARSING_ERR_MSG = "failed to parse"


def b64decode_pad(logger: logging.Logger, string: str) -> bytes:
    """b64 decoding and padding of missing "=" """
    logger.debug("Helper.b64decode_pad()")
    try:
        b64dec = base64.urlsafe_b64decode(string + "=" * (4 - len(string) % 4))
    except Exception:
        b64dec = b"ERR: b64 decoding error"
    return b64dec.decode("utf-8")


def b64_decode(logger: logging.Logger, string: str) -> str:
    """b64 decoding"""
    logger.debug("Helper.b64decode()")
    return convert_byte_to_string(base64.b64decode(string))


def b64_encode(logger: logging.Logger, string: str) -> str:
    """encode a bytestream in base64"""
    logger.debug("Helper.b64_encode()")
    return convert_byte_to_string(base64.b64encode(string))


def b64_url_encode(logger: logging.Logger, string: str) -> str:
    """encode a bytestream in base64 url and remove padding"""
    logger.debug("Helper.b64_url_encode()")
    string = convert_string_to_byte(string)
    encoded = base64.urlsafe_b64encode(string)
    return encoded.rstrip(b"=")


def b64_url_recode(logger: logging.Logger, string: str) -> str:
    """recode base64_url to base64"""
    logger.debug("Helper.b64_url_recode()")
    padding_factor = (4 - len(string) % 4) % 4
    string = convert_byte_to_string(string)
    string += "=" * padding_factor
    result = str(string).translate(dict(zip(map(ord, "-_"), "+/")))
    return result


def b64_url_decode(logger: logging.Logger, string: str) -> str:
    """decode base64url encoded string"""
    logger.debug("Helper.b64_url_decode()")
    # Remove whitespace
    string = string.strip()
    # Add padding if missing
    pad = "=" * (-len(string) % 4)
    string_padded = string + pad
    return convert_byte_to_string(base64.urlsafe_b64decode(string_padded))


def build_pem_file(logger: logging.Logger, existing, certificate, wrap, csr=False):
    """construct pem_file"""
    logger.debug("Helper.build_pem_file()")
    if csr:
        pem_file = f"-----BEGIN CERTIFICATE REQUEST-----\n{textwrap.fill(convert_byte_to_string(certificate), 64)}\n-----END CERTIFICATE REQUEST-----\n"
    else:
        if existing:
            if wrap:
                pem_file = f"{existing}-----BEGIN CERTIFICATE-----\n{textwrap.fill(convert_byte_to_string(certificate), 64)}\n-----END CERTIFICATE-----\n"
            else:
                pem_file = f"{convert_byte_to_string(existing)}-----BEGIN CERTIFICATE-----\n{convert_byte_to_string(certificate)}\n-----END CERTIFICATE-----\n"
        else:
            if wrap:
                pem_file = f"-----BEGIN CERTIFICATE-----\n{textwrap.fill(convert_byte_to_string(certificate), 64)}\n-----END CERTIFICATE-----\n"
            else:
                pem_file = f"-----BEGIN CERTIFICATE-----\n{convert_byte_to_string(certificate)}\n-----END CERTIFICATE-----\n"
    return pem_file


def ca_handler_load(
    logger: logging.Logger, config_dic: Dict
) -> importlib.import_module:
    """load and return ca_handler"""
    logger.debug("Helper.ca_handler_load()")

    if "CAhandler" not in config_dic:
        logger.error("CAhandler configuration missing in config file")
        return None

    if "handler_file" in config_dic["CAhandler"]:
        # try to load handler from file
        try:
            spec = importlib.util.spec_from_file_location(
                "CAhandler", config_dic["CAhandler"]["handler_file"]
            )
            ca_handler_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(ca_handler_module)
            return ca_handler_module
        except Exception as err_:
            logger.critical(
                "loading CAhandler configured in cfg failed with err: %s", err_
            )

    # if no 'handler_file' provided or loading was unsuccessful, try to load default handler
    try:
        ca_handler_module = importlib.import_module("acme_srv.ca_handler")
    except Exception as err_:
        logger.critical("loading default CAhandler failed with err: %s", err_)
        ca_handler_module = None

    return ca_handler_module


def config_check(logger: logging.Logger, config_dic: Dict):
    """check configuration"""
    logger.debug("Helper.config_check()")

    for section, section_dic in config_dic.items():
        for key, value in section_dic.items():
            if value.startswith('"') or value.endswith('"'):
                logger.warning(
                    'config_check(): section %s option: %s contains " characters. Check if this is really needed!',
                    section,
                    key,
                )


def config_profile_load(logger: logging.Logger, config_dic: Dict[str, str]):
    """load parameters"""
    logger.debug("Helper.config_profile_load()")

    # load profiles
    profiles = {}
    if "Order" in config_dic and "profiles" in config_dic["Order"]:
        try:
            profiles = json.loads(config_dic["Order"]["profiles"])
        except Exception as err_:
            logger.warning("loading profiles failed with error: %s", err_)

    logger.debug("Helper.config_profile_load() ended")
    return profiles


def config_eab_profile_load(logger: logging.Logger, config_dic: Dict[str, str]):
    """load parameters"""
    logger.debug("Helper.config_eab_profile_load()")

    eab_profiling = False
    eab_handler = None

    try:
        eab_profiling = config_dic.getboolean(
            "CAhandler", "eab_profiling", fallback=False
        )
    except Exception as err:
        logger.warning("loading eabprofile failed with error: %s", err)
        eab_profiling = False

    if eab_profiling:
        if (
            "EABhandler" in config_dic
            and "eab_handler_file" in config_dic["EABhandler"]
        ):
            # load eab_handler according to configuration
            eab_handler_module = eab_handler_load(logger, config_dic)
            if not eab_handler_module:
                logger.critical("EABHandler could not get loaded")
            else:
                eab_handler = eab_handler_module.EABhandler
        else:
            logger.critical("EABHandler configuration incomplete")

    logger.debug("_config_profile_load() ended")
    return eab_profiling, eab_handler


def config_headerinfo_load(logger: logging.Logger, config_dic: Dict[str, str]):
    """load parameters"""
    logger.debug("Helper.config_headerinfo_load()")

    header_info_field = None
    if (
        "Order" in config_dic
        and "header_info_list" in config_dic["Order"]
        and config_dic["Order"]["header_info_list"]
    ):
        try:
            header_info_field = json.loads(config_dic["Order"]["header_info_list"])[0]
        except Exception as err_:
            logger.warning("header_info_list failed with error: %s", err_)

    logger.debug("Helper.config_headerinfo_load() ended")
    return header_info_field


def config_enroll_config_log_load(logger: logging.Logger, config_dic: Dict[str, str]):
    """load parameters"""
    logger.debug("Helper.config_enroll_config_log_load()")

    enrollment_cfg_log = False
    enrollment_cfg_log_skip_list = []

    if "CAhandler" in config_dic:
        try:
            enrollment_cfg_log = config_dic.getboolean(
                "CAhandler", "enrollment_config_log", fallback=False
            )
        except Exception as err_:
            logger.warning("loading enrollment_config_log failed with error: %s", err_)

        if "enrollment_config_log_skip_list" in config_dic["CAhandler"]:
            try:
                enrollment_cfg_log_skip_list = json.loads(
                    config_dic["CAhandler"]["enrollment_config_log_skip_list"]
                )
            except Exception as err_:
                logger.warning(
                    "enrollment_config_log_skip_list failed with error: %s", err_
                )
                enrollment_cfg_log_skip_list = PARSING_ERR_MSG

    logger.debug(
        "Helper.config_enroll_config_log_load() ended with: %s", enrollment_cfg_log
    )
    return enrollment_cfg_log, enrollment_cfg_log_skip_list


def config_allowed_domainlist_load(logger: logging.Logger, config_dic: Dict[str, str]):
    """load parameters"""
    logger.debug("Helper.config_allowed_domainlist_load()")

    allowed_domainlist = []

    if "CAhandler" in config_dic and "allowed_domainlist" in config_dic["CAhandler"]:
        try:
            allowed_domainlist = json.loads(
                config_dic["CAhandler"]["allowed_domainlist"]
            )
        except Exception as err_:
            logger.warning("loading allowed_domainlist failed with error: %s", err_)
            allowed_domainlist = PARSING_ERR_MSG

    logger.debug(
        "Helper.config_allowed_domainlist_load() ended with: %s", allowed_domainlist
    )
    return allowed_domainlist


def eab_handler_load(
    logger: logging.Logger, config_dic: Dict
) -> importlib.import_module:
    """load and return eab_handler"""
    logger.debug("Helper.eab_handler_load()")
    # pylint: disable=w0621
    if "EABhandler" in config_dic and "eab_handler_file" in config_dic["EABhandler"]:
        # try to load handler from file
        try:
            spec = importlib.util.spec_from_file_location(
                "EABhandler", config_dic["EABhandler"]["eab_handler_file"]
            )
            eab_handler_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(eab_handler_module)
        except Exception as err_:
            logger.critical(
                "loading EABhandler configured in cfg failed with err: %s", err_
            )
            try:
                eab_handler_module = importlib.import_module("acme_srv.eab_handler")
            except Exception as err_:
                eab_handler_module = None
                logger.critical("loading default EABhandler failed with err: %s", err_)
    else:
        if "EABhandler" in config_dic:
            try:
                eab_handler_module = importlib.import_module("acme_srv.eab_handler")
            except Exception as err_:
                logger.critical("loading default EABhandler failed with err: %s", err_)
                eab_handler_module = None
        else:
            logger.error("EABhandler configuration missing in config file")
            eab_handler_module = None

    return eab_handler_module


def hooks_load(logger: logging.Logger, config_dic: Dict) -> importlib.import_module:
    """load and return hooks"""
    logger.debug("Helper.hooks_load()")

    hooks_module = None
    if "Hooks" in config_dic and "hooks_file" in config_dic["Hooks"]:
        # try to load hooks from file
        try:
            spec = importlib.util.spec_from_file_location(
                "Hooks", config_dic["Hooks"]["hooks_file"]
            )
            hooks_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(hooks_module)
        except Exception as err_:
            logger.critical(
                "Helper.hooks_load(): loading Hooks configured in cfg failed with err: %s",
                err_,
            )

    return hooks_module


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
        logger.error("cert_ski_pyopenssl_get(): No AKI found in certificate")
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
            cert.not_valid_before, _tformat="%Y-%m-%d %H:%M:%S"
        )
        expiration_date = date_to_uts_utc(
            cert.not_valid_after, _tformat="%Y-%m-%d %H:%M:%S"
        )
    except Exception:
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
    """get serial number form certificate"""
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
        logger.error("cert_san_get(): Error: %s", err)
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
        logger.error("cert_ski_pyopenssl_get(): No SKI found in certificate")
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
        logger.error("cert_ski_get(): Error: %s", err)
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
        logger.error("cryptography_version_get(): Error: %s", err)
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


def convert_byte_to_string(value: bytes) -> str:
    """convert a variable to string if needed"""
    if hasattr(value, "decode"):
        try:
            return value.decode()
        except Exception:
            return value
    else:
        return value


def convert_string_to_byte(value: str) -> bytes:
    """convert a variable to byte if needed"""
    if hasattr(value, "encode"):
        result = value.encode()
    else:
        result = value
    return result


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
            logger.error("csr_san_get(): Error: %s", err)

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


def decode_deserialize(logger: logging.Logger, string: str) -> Dict:
    """decode and deserialize string"""
    logger.debug("Helper.decode_deserialize()")
    # b64 decode
    string_decode = b64decode_pad(logger, string)
    # deserialize if b64 decoding was successful
    if string_decode and string_decode != "ERR: b64 decoding error":
        try:
            string_decode = json.loads(string_decode)
        except ValueError:
            string_decode = "ERR: Json decoding error"

    return string_decode


def decode_message(
    logger: logging.Logger, message: str
) -> Tuple[str, str, Dict[str, str], Dict[str, str], str]:
    """decode jwstoken and return header, payload and signature"""
    logger.debug("Helper.decode_message()")
    jwstoken = jws.JWS()
    result = False
    error = None
    try:
        jwstoken.deserialize(message)
        protected = json.loads(jwstoken.objects["protected"])
        if bool(jwstoken.objects["payload"]):
            payload = json.loads(jwstoken.objects["payload"])
        else:
            payload = {}
        signature = jwstoken.objects["signature"]
        result = True
    except Exception as err:
        logger.error("decode_message() err: %s", err)
        error = str(err)
        protected = {}
        payload = {}
        signature = None

    if payload:
        payload = dkeys_lower(payload)
    return (result, error, protected, payload, signature)


def dkeys_lower(tree: Dict[str, str]) -> Dict[str, str]:
    """lower characters in payload string"""
    if isinstance(tree, dict):
        result = {k.lower(): dkeys_lower(v) for k, v in tree.items()}
    elif isinstance(tree, list):
        result = [dkeys_lower(ele) for ele in tree]
    else:
        result = tree
    return result


def fqdn_in_san_check(logger: logging.Logger, san_list: List[str], fqdn: str) -> bool:
    """check if fqdn is in a list of sans"""
    logger.debug("Helper.fqdn_in_san_check([%s], %s)", san_list, fqdn)

    result = False
    if fqdn and san_list:
        for san in san_list:
            try:
                (_type, value) = san.lower().split(":", 1)
                if fqdn == value:
                    result = True
                    break
            except Exception:
                logger.error("ERROR: fqdn_in_san_check() SAN split failed: %s", san)

    logger.debug("Helper.fqdn_in_san_check() ended with: %s", result)
    return result


def generate_random_string(logger: logging.Logger, length: int) -> str:
    """generate random string to be used as name"""
    logger.debug("Helper.generate_random_string()")
    char_set = digits + ascii_letters
    return "".join(random.choice(char_set) for _ in range(length))


def get_url(environ: Dict[str, str], include_path: bool = False) -> str:
    """get url"""
    if "HTTP_HOST" in environ:
        server_name = html.escape(environ["HTTP_HOST"])
    else:
        server_name = "localhost"

    if "SERVER_PORT" in environ:
        port = html.escape(environ["SERVER_PORT"])
    else:
        port = 80

    if "HTTP_X_FORWARDED_PROTO" in environ:
        proto = html.escape(environ["HTTP_X_FORWARDED_PROTO"])
    elif "wsgi.url_scheme" in environ:
        proto = html.escape(environ["wsgi.url_scheme"])
    elif int(port) == 443:
        proto = "https"
    else:
        proto = "http"

    if include_path and "PATH_INFO" in environ:
        result = f'{proto}://{server_name}{html.escape(environ["PATH_INFO"])}'
    else:
        result = f"{proto}://{server_name}"
    return result


def client_parameter_validate(
    logger, csr: str, cahandler, value: str, value_list: List[str]
) -> Tuple[str, str]:
    """select value from list"""
    logger.debug("Helper.client_parameter_validate(%s)", value)

    value_to_set = None
    error = None
    if cahandler.profiles:
        logger.debug("Helper.client_parameter_validate(): using profile")
        # get profile info
        client_parameter = profile_lookup(logger, csr)
    else:
        logger.debug("Helper.client_parameter_validate(): using header info")
        # get header info
        client_parameter = header_info_lookup(
            logger, csr, cahandler.header_info_field, value
        )
    if client_parameter:
        if client_parameter in value_list:
            value_to_set = client_parameter
        else:
            error = f'{value} "{client_parameter}" is not allowed'
    else:
        # header not set, use first value from list
        value_to_set = value_list[0]

    logger.debug(
        "Helper.client_parameter_validate(%s) ended with %s/%s",
        value,
        value_to_set,
        error,
    )
    return value_to_set, error


def header_info_jsonify(logger: logging.Logger, header_info: str) -> Dict[str, str]:
    """jsonify header info"""
    logger.debug("Helper.header_info_json_parse()")

    header_info_dic = {}
    try:
        if isinstance(header_info, list) and "header_info" in header_info[-1]:
            header_info_dic = json.loads(header_info[-1]["header_info"])
    except Exception as err:
        logger.error("header_info_lookup() could not parse header_info_field: %s", err)

    logger.debug(
        "Helper.header_info_json_parse() ended with: %s", bool(header_info_dic)
    )
    return header_info_dic


def header_info_lookup(logger, csr: str, header_info_field, key: str) -> str:
    """lookup header info"""
    logger.debug("Helper.header_info_lookup(%s)", key)

    result = None
    header_info = header_info_get(logger, csr=csr)

    if header_info:
        header_info_dic = header_info_jsonify(logger, header_info)
        if header_info_field in header_info_dic:
            for ele in header_info_dic[header_info_field].split(" "):
                if key in ele.lower():
                    result = ele.split("=", 1)[1]
                    break
        else:
            logger.error(
                "header_info_lookup() header_info_field not found: %s",
                header_info_field,
            )

    logger.debug("Helper.header_info_lookup(%s) ended with: %s", key, result)
    return result


def header_info_get(
    logger: logging.Logger,
    csr: str,
    vlist: List[str] = ("id", "name", "header_info"),
    field_name: str = "csr",
) -> List[str]:
    """lookup header information"""
    logger.debug("Helper.header_info_get()")

    try:
        from acme_srv.db_handler import DBstore  # pylint: disable=c0415

        dbstore = DBstore(logger=logger)
        result = dbstore.certificates_search(field_name, csr, vlist)
    except Exception as err:
        result = []
        logger.error("Helper.header_info_get(): error: %s", err)

    return list(result)


def load_config(
    logger: logging.Logger = None, mfilter: str = None, cfg_file: str = None
) -> configparser.ConfigParser:
    """small configparser wrappter to load a config file"""
    if not cfg_file:
        if "ACME_SRV_CONFIGFILE" in os.environ:
            cfg_file = os.environ["ACME_SRV_CONFIGFILE"]
        else:
            cfg_file = os.path.dirname(__file__) + "/" + "acme_srv.cfg"
    if logger:
        logger.debug("load_config(%s:%s)", mfilter, cfg_file)
    config = configparser.ConfigParser(interpolation=None)
    config.optionxform = str
    config.read(cfg_file, encoding="utf8")
    return config


def parse_url(logger: logging.Logger, url: str) -> Dict[str, str]:
    """split url into pieces"""
    logger.debug("Helper.parse_url()")

    url_dic = {
        "proto": urlparse(url).scheme,
        "host": urlparse(url).netloc,
        "path": urlparse(url).path,
    }
    return url_dic


def encode_url(logger: logging.Logger, input_string: str) -> str:
    """urlencoding"""
    logger.debug("Helper.encode_url(%s)", input_string)

    return quote(input_string)


def _logger_nonce_modify(data_dic: Dict[str, str]) -> Dict[str, str]:
    """remove nonce from log entry"""
    if "header" in data_dic and "Replay-Nonce" in data_dic["header"]:
        data_dic["header"]["Replay-Nonce"] = "- modified -"
    return data_dic


def _logger_certificate_modify(
    data_dic: Dict[str, str], locator: str
) -> Dict[str, str]:
    """remove cert from log entry"""
    if "/acme/cert" in locator:
        data_dic["data"] = " - certificate - "
    return data_dic


def _logger_token_modify(data_dic: Dict[str, str]) -> Dict[str, str]:
    """remove token from challenge"""
    if "token" in data_dic["data"]:
        data_dic["data"]["token"] = "- modified -"
    return data_dic


def _logger_challenges_modify(data_dic: Dict[str, str]) -> Dict[str, str]:
    """remove token from challenge"""
    if "challenges" in data_dic["data"]:
        for challenge in data_dic["data"]["challenges"]:
            if "token" in challenge:
                challenge.update(
                    (k, "- modified - ") for k, v in challenge.items() if k == "token"
                )
    return data_dic


def logger_info(
    logger: logging.Logger, addr: str, locator: str, dat_dic: Dict[str, str]
):
    """log responses"""
    # create a copy of the dictionary
    data_dic = copy.deepcopy(dat_dic)

    data_dic = _logger_nonce_modify(data_dic)
    if "data" in data_dic:
        # remove cert from log entry
        data_dic = _logger_certificate_modify(data_dic, locator)

        # remove token
        data_dic = _logger_token_modify(data_dic)

        # remove token from challenge
        data_dic = _logger_challenges_modify(data_dic)

    logger.info("%s %s %s", addr, locator, str(data_dic))


def logger_setup(debug: bool) -> logging.Logger:
    """setup logger"""
    if debug:
        log_mode = logging.DEBUG
    else:
        log_mode = logging.INFO

    config_dic = load_config()

    # define standard log format
    log_format = "%(message)s"
    if "Helper" in config_dic and "log_format" in config_dic["Helper"]:
        log_format = config_dic["Helper"]["log_format"]

    logging.basicConfig(format=log_format, datefmt="%Y-%m-%d %H:%M:%S", level=log_mode)
    logger = logging.getLogger("acme2certifier")
    return logger


def print_debug(debug: bool, text: str):
    """little helper to print debug messages"""
    if debug:
        print(f"{datetime.datetime.now()}: {text}")


def jwk_thumbprint_get(logger: logging.Logger, pub_key: Dict[str, str]) -> str:
    """get thumbprint"""
    logger.debug("Helper.jwk_thumbprint_get()")
    if pub_key:
        try:
            jwkey = jwk.JWK(**pub_key)
            thumbprint = jwkey.thumbprint()
        except Exception as err:
            logger.error("jwk_thumbprint_get(): error: %s", err)
            thumbprint = None
    else:
        thumbprint = None

    logger.debug("Helper.jwk_thumbprint_get() ended with: %s", thumbprint)
    return thumbprint


def sha256_hash(logger: logging.Logger, string: str) -> str:
    """hash string"""
    logger.debug("Helper.sha256_hash()")
    result = hashlib.sha256(string.encode("utf-8")).digest()
    logger.debug(
        "Helper.sha256_hash() ended with %s (base64-encoded)",
        b64_encode(logger, result),
    )
    return result


def sha256_hash_hex(logger: logging.Logger, string: str) -> str:
    """hash string"""
    logger.debug("Helper.sha256_hash_hex()")
    result = hashlib.sha256(string.encode("utf-8")).hexdigest()
    logger.debug("Helper.sha256_hash_hex() ended with %s", result)
    return result


def signature_check(
    logger: logging.Logger, message: str, pub_key: str, json_: bool = False
) -> Tuple[bool, str]:
    """check JWS"""
    logger.debug("Helper.signature_check(%s)", json_)

    result = False
    error = None

    if pub_key:
        # load key
        try:
            if json_:
                logger.debug("Helper.signature_check(): load key from json")
                jwkey = jwk.JWK.from_json(pub_key)
            else:
                logger.debug("Helper.signature_check(): load plain json")
                jwkey = jwk.JWK(**pub_key)
        except Exception as err:
            logger.error("load key failed %s", err)
            jwkey = None
            result = False
            error = str(err)

        # verify signature
        if jwkey:
            jwstoken = jws.JWS()
            jwstoken.deserialize(message)
            try:
                jwstoken.verify(jwkey)
                result = True
            except Exception as err:
                logger.error("verify failed %s", err)
                error = str(err)
        else:
            logger.error("No jwkey extracted")
    else:
        logger.error("No pubkey specified.")
        error = "No key specified."

    logger.debug("Helper.signature_check() ended with: %s, %s", result, error)
    return (result, error)


def string_sanitize(logger: logging.Logger, unsafe_str: str) -> str:
    """sanitize string"""
    logger.debug("Helper.string_sanitize()")
    allowed_range = set(range(32, 127))
    safe_str = ""
    for char in unsafe_str:
        cp_ = ord(char)
        if cp_ in allowed_range:
            safe_str += char
        elif cp_ == 9:
            safe_str += " " * 4
    return re.sub(r"\s+", " ", safe_str)


def _fqdn_resolve(
    logger: logging.Logger,  # pylint: disable=W0613
    req: dns.resolver.Resolver,
    host: str,
    catch_all: bool = False,
) -> Tuple[str, bool]:
    """resolve hostname"""
    logger.debug("Helper._fqdn_resolve(%s:%s)", host, catch_all)

    if catch_all:
        result = []
    else:
        result = None

    invalid = True
    for rrtype in ["A", "AAAA"]:
        try:
            answers = req.resolve(host, rrtype)
            logger.debug("Helper._fqdn_resolve() got answer: %s", list(answers))
            for rdata in answers:
                invalid = False
                if catch_all:
                    result.append(str(rdata))
                else:
                    result = str(rdata)
                    break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            logger.debug("No answer for %s with type %s", host, rrtype)
            if not result:
                invalid = True
        except Exception as err:
            logger.debug("Error while resolving %s with type %s: %s", host, rrtype, err)
            invalid = False

        if not catch_all and result is not None:
            break

    logger.debug("Helper._fqdn_resolve(%s) ended with: %s, %s", host, result, invalid)
    return (result, invalid)


def fqdn_resolve(
    logger: logging.Logger, host: str, dnssrv: List[str] = None, catch_all: bool = False
) -> Tuple[str, bool]:
    """dns resolver"""
    logger.debug("Helper.fqdn_resolve(%s catch_all: %s)", host, catch_all)
    req = dns.resolver.Resolver()

    # hack to cover github workflows
    if "." in host:
        if dnssrv:
            # add specific dns server
            req.nameservers = dnssrv
        # resolve hostname
        (result, invalid) = _fqdn_resolve(logger, req, host, catch_all=catch_all)

    else:
        result = None
        invalid = False

    logger.debug("Helper.fqdn_resolve(%s) ended with: %s, %s", host, result, invalid)
    return (result, invalid)


def dns_server_list_load() -> List[str]:
    """load dns-server from config file"""
    config_dic = load_config()

    # define default dns servers
    default_dns_server_list = ["9.9.9.9", "8.8.8.8"]

    if "Challenge" in config_dic:
        if "dns_server_list" in config_dic["Challenge"]:
            try:
                dns_server_list = json.loads(config_dic["Challenge"]["dns_server_list"])
            except Exception:
                dns_server_list = default_dns_server_list
        else:
            dns_server_list = default_dns_server_list
    else:
        dns_server_list = default_dns_server_list

    return dns_server_list


def error_dic_get(logger: logging.Logger) -> Dict[str, str]:
    """load acme error messages"""
    logger.debug("Helper.error_dict_get()")
    # this is the main dictionary
    error_dic = {
        "accountdoesnotexist": "urn:ietf:params:acme:error:accountDoesNotExist",
        "alreadyrevoked": "urn:ietf:params:acme:error:alreadyRevoked",
        "badcsr": "urn:ietf:params:acme:error:badCSR",
        "badpubkey": "urn:ietf:params:acme:error:badPublicKey",
        "badrevocationreason": "urn:ietf:params:acme:error:badRevocationReason",
        "externalaccountrequired": "urn:ietf:params:acme:error:externalAccountRequired",
        "invalidcontact": "urn:ietf:params:acme:error:invalidContact",
        "invalidprofile": "urn:ietf:params:acme:error:invalidProfile",
        "malformed": "urn:ietf:params:acme:error:malformed",
        "ordernotready": "urn:ietf:params:acme:error:orderNotReady",
        "ratelimited": "urn:ietf:params:acme:error:rateLimited",
        "rejectedidentifier": "urn:ietf:params:acme:error:rejectedIdentifier",
        "serverinternal": "urn:ietf:params:acme:error:serverInternal",
        "unauthorized": "urn:ietf:params:acme:error:unauthorized",
        "unsupportedidentifier": "urn:ietf:params:acme:error:unsupportedIdentifier",
        "useractionrequired": "urn:ietf:params:acme:error:userActionRequired",
    }
    return error_dic


def patched_create_connection(address: List[str], *args, **kwargs):  # pragma: no cover
    """Wrap urllib3's create_connection to resolve the name elsewhere"""
    # load dns-servers from config file
    dns_server_list = dns_server_list_load()
    # resolve hostname to an ip address; use your own resolver
    host, port = address
    (hostname, _invalid) = fqdn_resolve(host, dns_server_list)
    # pylint: disable=W0212
    return connection._orig_create_connection((hostname, port), *args, **kwargs)


def proxy_check(
    logger: logging.Logger, fqdn: str, proxy_server_list: Dict[str, str]
) -> str:
    """check proxy server"""
    logger.debug("Helper.proxy_check(%s)", fqdn)

    # remove leading *.
    proxy_server_list_new = {
        k.replace("*.", ""): v for k, v in proxy_server_list.items()
    }

    proxy = None
    for regex in sorted(proxy_server_list_new.keys(), reverse=True):
        if regex != "*":
            regex_compiled = re.compile(regex)
            if bool(regex_compiled.search(fqdn)):
                # parameter is in - set flag accordingly and stop loop
                proxy = proxy_server_list_new[regex]
                logger.debug(
                    "Helper.proxy_check() match found: fqdn: %s, regex: %s", fqdn, regex
                )
                break

    if "*" in proxy_server_list_new.keys() and not proxy:
        logger.debug("Helper.proxy_check() wildcard match found: fqdn: %s", fqdn)
        proxy = proxy_server_list_new["*"]

    logger.debug("Helper.proxy_check() ended with %s", proxy)
    return proxy


def url_get_with_own_dns(logger: logging.Logger, url: str, verify: bool = True) -> str:
    """request by using an own dns resolver"""
    logger.debug("Helper.url_get_with_own_dns(%s)", url)
    # patch an own connection handler into URL lib
    # pylint: disable=W0212
    connection._orig_create_connection = connection.create_connection
    connection.create_connection = patched_create_connection
    try:
        req = requests.get(
            url,
            verify=verify,
            headers={
                "Connection": "close",
                "Accept-Encoding": "gzip",
                "User-Agent": USER_AGENT,
            },
            timeout=20,
        )
        result = req.text
    except Exception as err_:
        result = None
        logger.error("Helper.url_get_with_own_dns error: %s", err_)
    # cleanup
    connection.create_connection = connection._orig_create_connection
    return result


def allowed_gai_family() -> socket.AF_INET:
    """set family"""
    family = socket.AF_INET  # force IPv4
    return family


def url_get_with_default_dns(
    logger: logging.Logger,
    url: str,
    proxy_list: Dict[str, str],
    verify: bool,
    timeout: int,
) -> str:
    """http get with default dns server"""
    logger.debug(
        "Helper.url_get_with_default_dns(%s) vrf=%s, timout:%s", url, verify, timeout
    )

    # we need to tweak headers and url for ipv6 addresse
    (headers, url) = v6_adjust(logger, url)

    try:
        req = requests.get(
            url, verify=verify, timeout=timeout, headers=headers, proxies=proxy_list
        )
        result = req.text
    except Exception as err_:
        logger.debug("Helper.url_get(%s): error", err_)
        # force fallback to ipv4
        logger.debug("Helper.url_get(%s): fallback to v4", url)
        old_gai_family = urllib3_cn.allowed_gai_family
        try:
            urllib3_cn.allowed_gai_family = allowed_gai_family
            req = requests.get(
                url,
                verify=verify,
                timeout=timeout,
                headers={
                    "Connection": "close",
                    "Accept-Encoding": "gzip",
                    "User-Agent": USER_AGENT,
                },
                proxies=proxy_list,
            )
            result = req.text
        except Exception as err:
            result = None
            logger.error("url_get error: %s", err)
        urllib3_cn.allowed_gai_family = old_gai_family

    return result


def url_get(
    logger: logging.Logger,
    url: str,
    dns_server_list: List[str] = None,
    proxy_server=None,
    verify=True,
    timeout=20,
) -> str:
    """http get"""
    logger.debug("Helper.url_get(%s) vrf=%s, timout:%s", url, verify, timeout)
    # pylint: disable=w0621
    # configure proxy servers if specified
    if proxy_server:
        proxy_list = {"http": proxy_server, "https": proxy_server}
    else:
        proxy_list = {}
    if dns_server_list and not proxy_server:
        result = url_get_with_own_dns(logger, url, verify)
    else:
        result = url_get_with_default_dns(logger, url, proxy_list, verify, timeout)

    logger.debug("Helper.url_get() ended with: %s", result)
    return result


def txt_get(logger: logging.Logger, fqdn: str, dns_srv: List[str] = None) -> List[str]:
    """dns query to get the TXt record"""
    logger.debug("Helper.txt_get(%s: %s)", fqdn, dns_srv)

    # rewrite dns resolver if configured
    if dns_srv:
        dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
        dns.resolver.default_resolver.nameservers = dns_srv
    txt_record_list = []
    try:
        response = dns.resolver.resolve(fqdn, "TXT")
        for rrecord in response:
            txt_record_list.append(rrecord.strings[0])
    except Exception as err_:
        logger.error("txt_get() error: %s", err_)
    logger.debug("Helper.txt_get() ended with: %s", txt_record_list)
    return txt_record_list


def uts_now():
    """unixtimestamp in utc"""
    return calendar.timegm(datetime.datetime.now(datetime.timezone.utc).utctimetuple())


def uts_to_date_utc(uts: int, tformat: str = "%Y-%m-%dT%H:%M:%SZ") -> str:
    """convert unix timestamp to date format"""
    return datetime.datetime.fromtimestamp(int(uts), tz=pytz.utc).strftime(tformat)


def date_to_uts_utc(date_human: str, _tformat: str = "%Y-%m-%dT%H:%M:%S") -> int:
    """convert date to unix timestamp"""
    if isinstance(date_human, datetime.datetime):
        # we already got an datetime object as input
        result = calendar.timegm(date_human.timetuple())
    else:
        result = int(calendar.timegm(parse(date_human).timetuple()))
    return result


def date_to_datestr(
    date: datetime.datetime, tformat: str = "%Y-%m-%dT%H:%M:%SZ"
) -> str:
    """convert dateobj to datestring"""
    try:
        result = date.strftime(tformat)
    except Exception:
        result = None
    return result


def datestr_to_date(datestr: str, tformat: str = "%Y-%m-%dT%H:%M:%S") -> str:
    """convert datestr to dateobj"""
    try:
        result = datetime.datetime.strptime(datestr, tformat)
    except Exception:
        result = None
    return result


def proxystring_convert(
    logger: logging.Logger, proxy_server: str
) -> Tuple[str, str, str]:
    """convert proxy string"""
    logger.debug("Helper.proxystring_convert(%s)", proxy_server)

    proxy_proto_dic = {
        "http": socks.PROXY_TYPE_HTTP,
        "socks4": socks.PROXY_TYPE_SOCKS4,
        "socks5": socks.PROXY_TYPE_SOCKS5,
    }
    try:
        (proxy_proto, proxy) = proxy_server.split("://")
    except Exception:
        logger.error(
            "proxystring_convert(): error splitting proxy_server string: %s",
            proxy_server,
        )
        proxy = None
        proxy_proto = None

    if proxy:
        try:
            (proxy_addr, proxy_port) = proxy.split(":")
        except Exception:
            logger.error(
                "proxystring_convert(): error splitting proxy into host/port: %s", proxy
            )
            proxy_addr = None
            proxy_port = None
    else:
        proxy_addr = None
        proxy_port = None

    if proxy_proto and proxy_addr and proxy_port:
        try:
            proto_string = proxy_proto_dic[proxy_proto]
        except Exception:
            logger.error(
                "proxystring_convert(): unknown proxy protocol: %s", proxy_proto
            )
            proto_string = None
    else:
        logger.error(
            "proxystring_convert(): proxy_proto (%s), proxy_addr (%s) or proxy_port (%s) missing",
            proxy_proto,
            proxy_addr,
            proxy_port,
        )
        proto_string = None

    try:
        proxy_port = int(proxy_port)
    except Exception:
        logger.error("proxystring_convert(): unknown proxy port: %s", proxy_port)
        proxy_port = None

    logger.debug(
        "Helper.proxystring_convert() ended with %s, %s, %s",
        proto_string,
        proxy_addr,
        proxy_port,
    )
    return (proto_string, proxy_addr, proxy_port)


def servercert_get(
    logger: logging.Logger,
    hostname: str,
    port: int = 443,
    proxy_server: str = None,
    sni: str = None,
) -> str:
    """get server certificate from an ssl connection"""
    logger.debug("Helper.servercert_get(%s:%s)", hostname, port)

    pem_cert = None

    if ipv6_chk(logger, hostname):
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    else:
        sock = socks.socksocket()

    # backup - set sni to hostname
    if not sni:
        sni = hostname

    context = ssl.create_default_context()  # NOSONAR
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # NOSONAR
    context.options |= ssl.PROTOCOL_TLS_CLIENT
    context.set_alpn_protocols(["acme-tls/1"])
    # reject insecure ssl version
    try:
        # this does not work on RH8
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception:  # pragma: no cover
        logger.error("servercert_get(): minimum_version not supported")

    context.options |= ssl.OP_NO_SSLv3
    context.options |= ssl.OP_NO_TLSv1
    context.options |= ssl.OP_NO_TLSv1_1

    if proxy_server:
        (proxy_proto, proxy_addr, proxy_port) = proxystring_convert(
            logger, proxy_server
        )
        if proxy_proto and proxy_addr and proxy_port:
            logger.debug("servercert_get(): configure proxy")
            sock.setproxy(proxy_proto, proxy_addr, port=proxy_port)
    try:
        sock.connect((hostname, port))
        with context.wrap_socket(sock, server_hostname=sni) as sslsock:
            logger.debug(
                "servercert_get(): %s:%s:%s version: %s",
                hostname,
                sni,
                port,
                sslsock.version(),
            )
            der_cert = sslsock.getpeercert(True)
            # from binary DER format to PEM
            if der_cert:
                pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
    except Exception as err_:
        logger.error("servercert_get() failed with: %s", err_)
        pem_cert = None

    if pem_cert:
        logger.debug(
            "Helper.servercert_get() ended with: %s",
            b64_encode(logger, convert_string_to_byte(pem_cert)),
        )
    else:
        logger.debug("Helper.servercert_get() ended with: None")
    return pem_cert


def validate_csr(logger: logging.Logger, order_dic: Dict[str, str], _csr) -> bool:
    """validate certificate signing request against order"""
    logger.debug("Helper.validate_csr(%s)", order_dic)
    return True


def validate_email(logger: logging.Logger, contact_list: List[str]) -> bool:
    """validate contact against RFC608"""
    logger.debug("Helper.validate_email()")
    result = True
    pattern = r"^[A-Za-z0-9\.\+_-]+@[A-Za-z]+[A-Za-z0-9\._-]+[A-Za-z0-9]+\.[a-zA-Z\.]+[a-zA-Z]+$"
    # check if we got a list or single address
    if isinstance(contact_list, list):
        for contact in contact_list:
            contact = contact.replace("mailto:", "")
            contact = contact.lstrip()
            tmp_result = bool(re.search(pattern, contact))
            logger.debug("# validate: %s result: %s", contact, tmp_result)
            if not tmp_result:
                result = tmp_result
    else:
        contact_list = contact_list.replace("mailto:", "")
        contact_list = contact_list.lstrip()
        result = bool(re.search(pattern, contact_list))
        logger.debug(
            "Helper.validate_email() of: %s emded with result: %s", contact_list, result
        )
    return result


def validate_identifier(
    logger: logging.Logger,
    id_type: str,
    identifier: str,
    tnauthlist_support: bool = False,
) -> bool:
    """validate identifier"""
    logger.debug("Helper.validate_identifier()")

    result = False
    if identifier:
        if id_type == "dns":
            result = validate_fqdn(logger, identifier)
        elif id_type == "ip":
            result = validate_ip(logger, identifier)
        elif id_type == "tnauthlist" and tnauthlist_support:
            result = True

    logger.debug("Helper.validate_identifier() ended with: %s", result)
    return result


def validate_ip(logger: logging.Logger, ip: str) -> bool:
    """validate ip address"""
    logger.debug("Helper.validate_ip()")
    try:
        ipaddress.ip_address(ip)
        result = True
    except ValueError:
        result = False
    logger.debug("Helper.validate_ip() ended with: %s", result)
    return result


def validate_fqdn(logger: logging.Logger, fqdn: str) -> bool:
    """validate fqdn"""
    logger.debug("Helper.validate_fqdn()")

    result = False
    regex = r"^(([a-z0-9]\-*[a-z0-9]*){1,63}\.?){1,255}$"
    p = re.compile(regex)
    if re.search(p, fqdn):
        result = True

    if not result:
        logger.debug(
            "Helper.validate_fqdn(): invalid fqdn. Check for wildcard : %s", fqdn
        )
        regex = r"^\*\.[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$"
        p = re.compile(regex)
        if re.search(p, fqdn):
            result = True

    logger.debug("Helper.validate_fqdn() ended with: %s", result)
    return result


def handle_exception(exc_type, exc_value, exc_traceback):  # pragma: no cover
    """exception handler"""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    # logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))
    logging.error("Uncaught exception")


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


def ip_validate(logger: logging.Logger, ip_addr: str) -> Tuple[str, bool]:
    """validate ip address"""
    logger.debug("Helper.ip_validate(%s)", ip_addr)

    try:
        reverse_pointer = ipaddress.ip_address(ip_addr).reverse_pointer
        invalid = False
    except ValueError:
        reverse_pointer = None
        invalid = True
    logger.debug("Helper.ip_validate() ended with: %s:%s", reverse_pointer, invalid)
    return (reverse_pointer, invalid)


def v6_adjust(logger: logging.Logger, url: str) -> Tuple[Dict[str, str], str]:
    """corner case for v6 addresses"""
    logger.debug("Helper.v6_adjust(%s)", url)

    headers = {
        "Connection": "close",
        "Accept-Encoding": "gzip",
        "User-Agent": USER_AGENT,
    }

    url_dic = parse_url(logger, url)

    # adjust headers and url in case we have an ipv6address
    if ipv6_chk(logger, url_dic["host"]):
        headers["Host"] = url_dic["host"]
        url = f"{url_dic['proto']}://[{url_dic['host']}]/{url_dic['path']}"

    logger.debug("Helper.v6_adjust() ended")
    return (headers, url)


def ipv6_chk(logger: logging.Logger, address: str) -> bool:
    """check if an address is ipv6"""
    logger.debug("Helper.ipv6_chk(%s)", address)

    try:
        # we need to set a host header and braces for ipv6 headers and
        if isinstance(ipaddress.ip_address(address), ipaddress.IPv6Address):
            logger.debug("Helper.v6_adjust(}): ipv6 address detected")
            result = True
        else:
            result = False
    except Exception:
        result = False

    logger.debug("Helper.ipv6_chk() ended with %s", result)
    return result


def encode_domain(logger, domain: str) -> bytes:
    """encode domain"""
    logger.debug("Helper.encode_domain(%s)", domain)

    # Handle wildcard input *before* IDNA decoding.
    if domain.startswith("*."):
        domain = domain[2:]

    encoded_domain = None
    try:
        encoded_domain = idna.encode(domain)
    except Exception as err:
        logger.error(f"Invalid domain format in csr: {err}")

    return encoded_domain


def wildcard_domain_check(
    logger: logging.Logger, domain: str, encoded_domain: str, encoded_pattern_base: str
) -> bool:
    """compare domain to whitelist returns false if not matching"""
    logger.debug("Helper.domain_check(%s)", domain)

    result = False
    if domain.startswith("*."):
        # Both input and pattern are wildcards. Check if input domain base includes the pattern
        if encoded_domain.endswith(encoded_pattern_base):
            result = True
    else:
        # Input is not a wildcard, pattern is. Check endswith. Add '.' to pattern base so it's not approving the base domain
        # for example domain foo.bar shouldn't match with pattern *.foo.bar
        if encoded_domain.endswith(b"." + encoded_pattern_base):
            result = True
    logger.debug("Helper.domain_check() ended with %s", result)
    return result


def pattern_check(logger, domain, pattern):
    """compare domain to whitelist returns false if not matching"""
    logger.debug("Helper.pattern_check(%s, %s)", domain, pattern)

    pattern = pattern.lower().strip()
    encoded_pattern = encode_domain(logger, pattern)
    encoded_domain = encode_domain(logger, domain)

    result = False
    if encoded_pattern:
        if pattern.startswith("*."):
            result = wildcard_domain_check(
                logger, domain, encoded_domain, encoded_pattern
            )
        else:
            if not domain.startswith("*.") and encoded_domain == encoded_pattern:
                result = True
    else:
        logger.error(f"Invalid pattern configured in allowed_domainlist: {pattern}")

    logger.debug("Helper.pattern_check() ended with %s", result)
    return result


def is_domain_whitelisted(
    logger: logging.Logger, domain: str, whitelist: List[str]
) -> bool:
    """compare domain to whitelist returns false if not matching"""
    logger.debug("Helper.is_domain_whitelisted(%s)", domain)

    result = False
    if domain:
        domain = domain.lower().strip()
        for pattern in whitelist:
            # corner-case blank entry
            if not pattern:
                logger.error(
                    "Invalid pattern configured in allowed_domainlist: empty string"
                )
                continue
            result = pattern_check(logger, domain, pattern)
            if result:
                break

    logger.debug("Helper.is_domain_whitelisted() ended with %s", result)
    return result


def allowed_domainlist_check(
    logger: logging.Logger, csr, allowed_domain_list: List[str]
) -> str:
    """check if domain is in allowed domain list"""
    logger.debug("Helper.allowed_domainlist_check()")

    error = None
    if allowed_domain_list:
        (san_list, check_list) = sancheck_lists_create(logger, csr)
        invalid_domains = []

        # go over the san list and check each entry
        for san in san_list:
            if not is_domain_whitelisted(logger, san, allowed_domain_list):
                invalid_domains.append(san)
                error = "Either CN or SANs are not allowed by configuration"

        if check_list:
            error = f"SAN list parsing failed {check_list}"

        logger.debug(
            f'Helper._allowed_domainlist_check() ended with {error} for {",".join(invalid_domains)}'
        )
    return error


def sancheck_lists_create(logger, csr: str) -> Tuple[List[str], List[str]]:
    """create lists for san check"""
    logger.debug("Helper.sancheck_lists_create()")

    check_list = []
    san_list = []

    # get sans and build a list
    _san_list = csr_san_get(logger, csr)

    if _san_list:
        for san in _san_list:
            try:
                # SAN list must be modified/filtered)
                (_san_type, san_value) = san.lower().split(":")
                san_list.append(san_value)
            except Exception:
                # force check to fail as something went wrong during parsing
                check_list.append(san)
                logger.debug(
                    "Helper.sancheck_lists_create(): san_list parsing failed at entry: $s",
                    san,
                )

    # get common name and attach it to san_list
    cn = csr_cn_get(logger, csr)

    if cn:
        cn = cn.lower()
        if cn not in san_list:
            # append cn to san_list
            logger.debug("Helper.sancheck_lists_create()): append cn to san_list")
            san_list.append(cn)

    return (san_list, check_list)


def profile_lookup(logger: logging.Logger, csr: str) -> str:
    """get profile name from csr"""
    logger.debug("Helper.profile_lookup()")

    from acme_srv.db_handler import DBstore  # pylint: disable=c0415

    dbstore = DBstore(logger=logger)

    try:
        result = dbstore.certificates_search(
            "csr", csr, ["id", "order_id", "order__profile"]
        )
    except Exception as err:
        logger.error("Helper.profile_lookup() failed with: %s", err)
        result = None
    if result and "order__profile" in result[0]:
        # we have a match - get profile name
        profile_name = result[0]["order__profile"]
    else:
        profile_name = None

    logger.debug("Helper.profile_lookup() ended with: %s", profile_name)
    return profile_name


def eab_profile_header_info_check(
    logger: logging.Logger,
    cahandler,
    csr: str,
    handler_hifield: str = "profile_name",
) -> str:
    """check profile"""
    logger.debug("Helper.eab_profile_header_info_check()")

    if cahandler.eab_profiling:
        # eab profiling - check if we have a handler
        if cahandler.eab_handler:
            # profiling enabled - check profile
            error = eab_profile_check(logger, cahandler, csr, handler_hifield)
        else:
            logger.error(
                "eab_profile_header_info_check(): eab_profiling enabled but no handler defined"
            )
            error = "Eab_profiling enabled but no handler defined"

    elif cahandler.profiles:
        # acme profiling - acme profiling will always be preferred
        profile = profile_lookup(logger, csr)
        if profile:
            logger.debug(
                "Helper.profile_lookup(): setting %s to %s",
                handler_hifield,
                profile,
            )
            setattr(cahandler, handler_hifield, profile)
        error = None

    elif cahandler.header_info_field:
        # no profiling - parse profileid from http_header
        hil_value = header_info_lookup(
            logger, csr, cahandler.header_info_field, handler_hifield
        )
        if hil_value:
            logger.debug(
                "Helper.eab_profile_header_info_check(): setting %s to %s",
                handler_hifield,
                hil_value,
            )
            logger.info(
                "Received enrollment parameter: %s value: %s via headerinfo field",
                handler_hifield,
                hil_value,
            )
            setattr(cahandler, handler_hifield, hil_value)
            error = None
        else:
            logger.debug("eab_profile_header_info_check(): no header_info field found")
            error = None
    else:
        # no profiling - no header_info_field
        error = None

    logger.debug("Helper.eab_profile_header_info_check() ended with %s", error)
    return error


def cn_validate(logger: logging.Logger, cn: str) -> bool:
    """validate common name"""
    logger.debug("Helper.cn_validate(%s)", cn)

    error = False
    if cn:
        # check if CN is a valid IP address
        result = validate_ip(logger, cn)
        if not result:
            # check if CN is a valid fqdn
            result = validate_fqdn(logger, cn)
        if not result:
            error = "Profile subject check failed: CN validation failed"
    else:
        error = "Profile subject check failed: commonName missing"

    logger.debug("Helper.cn_validate() ended with: %s", error)
    return error


def eab_profile_subject_string_check(
    logger: logging.Logger, profile_subject_dic, key: str, value: str
) -> str:
    """check if a for a string value taken from profile if its a variable inside a class and apply value"""
    logger.debug(
        "Helper.eab_profile_subject_string_check(): string: key: %s, value: %s",
        key,
        value,
    )

    error = False
    if key == "commonName":
        # check if CN is a valid IP address or fqdn
        error = cn_validate(logger, value)
    elif key in profile_subject_dic:
        if isinstance(profile_subject_dic[key], str) and (
            value == profile_subject_dic[key] or profile_subject_dic[key] == "*"
        ):
            logger.debug(
                "Helper.eab_profile_subject_check() successul for string : %s", key
            )
            del profile_subject_dic[key]
        elif (
            isinstance(profile_subject_dic[key], list)
            and value in profile_subject_dic[key]
        ):
            logger.debug(
                "Helper.eab_profile_subject_check() successul for list : %s", key
            )
            del profile_subject_dic[key]
        else:
            logger.error(
                "Helper.eab_profile_subject_check() failed for: %s: value: %s expected: %s",
                key,
                value,
                profile_subject_dic[key],
            )
            error = f"Profile subject check failed for {key}"
    else:
        logger.error("Helper.eab_profile_subject_check() failed for: %s", key)
        error = f"Profile subject check failed for {key}"

    logger.debug("Helper.eab_profile_subject_string_check() ended")
    return error


def eab_profile_subject_check(
    logger: logging.Logger, csr: str, profile_subject_dic: str
) -> str:
    """check subject against profile information"""
    logger.debug("Helper.eab_profile_subject_check()")
    error = None

    # get subject from csr
    subject_dic = csr_subject_get(logger, csr)

    # check if all profile subject entries are in csr
    for key, value in subject_dic.items():
        error = eab_profile_subject_string_check(
            logger, profile_subject_dic, key, value
        )
        if error:
            break

    # check if we have any entries left in the profile_subject_dic
    if not error and profile_subject_dic:
        logger.error(
            "Helper.eab_profile_subject_check() failed for: %s",
            list(profile_subject_dic.keys()),
        )
        error = "Profile subject check failed"

    logger.debug("Helper.eab_profile_subject_check() ended with: %s", error)
    return error


def eab_profile_revocation_check(
    logger: logging.Logger, cahandler, certificate_raw: str
):
    """check eab profile for revocation"""
    logger.debug("Helper.eab_profile_revocation_check()")
    with cahandler.eab_handler(logger) as eab_handler:
        eab_profile_dic = eab_handler.eab_profile_get(
            b64_url_recode(logger, certificate_raw), revocation=True
        )
        for key, value in eab_profile_dic.items():
            if key in ["subject", "allowed_domainlist"]:
                continue
            elif isinstance(value, str):
                eab_profile_string_check(logger, cahandler, key, value)
            elif isinstance(value, list):
                # check if we need to execute a function from the handler
                if "eab_profile_list_check" in dir(cahandler):
                    _result = cahandler.eab_profile_list_check(
                        eab_handler, certificate_raw, key, value
                    )
                else:
                    _result = eab_profile_list_check(
                        logger, cahandler, eab_handler, certificate_raw, key, value
                    )

    logger.debug("Helper.eab_profile_revocation_check() ended")


def eab_profile_check(
    logger: logging.Logger, cahandler, csr: str, handler_hifield: str
) -> str:
    """check eab profile"""
    logger.debug("Helper.eab_profile_check()")

    result = None
    with cahandler.eab_handler(logger) as eab_handler:
        eab_profile_dic = eab_handler.eab_profile_get(csr)
        for key, value in eab_profile_dic.items():
            if key == "subject":
                result = eab_profile_subject_check(logger, csr, value)
            elif isinstance(value, str):
                eab_profile_string_check(logger, cahandler, key, value)
            elif isinstance(value, list):
                # check if we need to execute a function from the handler
                if "eab_profile_list_check" in dir(cahandler):
                    result = cahandler.eab_profile_list_check(
                        eab_handler, csr, key, value
                    )
                else:
                    result = eab_profile_list_check(
                        logger, cahandler, eab_handler, csr, key, value
                    )
            if result:
                break

        # we need to reject situations where profiling is enabled but the header_hifiled is not defined in json
        if cahandler.header_info_field and handler_hifield not in eab_profile_dic:
            hil_value = header_info_lookup(
                logger, csr, cahandler.header_info_field, handler_hifield
            )
            if hil_value:
                # setattr(self, handler_hifield, hil_value)
                result = (
                    f'header_info field "{handler_hifield}" is not allowed by profile'
                )

    logger.debug("Helper.eab_profile_check() ended with: %s", result)
    return result


def eab_profile_list_check(logger, cahandler, eab_handler, csr, key, value):
    """check if a for a list value taken from profile if its a variable inside a class and apply value"""
    logger.debug(
        "Helper.eab_profile_list_check(): list: key: %s, value: %s", key, value
    )

    result = None
    if hasattr(cahandler, key) and key != "allowed_domainlist":
        new_value, error = client_parameter_validate(logger, csr, cahandler, key, value)
        if new_value:
            logger.debug(
                "Helper.eab_profile_list_check(): setting attribute: %s to %s",
                key,
                new_value,
            )
            setattr(cahandler, key, new_value)
        else:
            result = error
    elif key == "allowed_domainlist":
        # check if csr contains allowed domains
        if "allowed_domains_check" in dir(eab_handler):
            # execute a function from eab_handler
            logger.info("Execute allowed_domains_check() from eab handler")
            error = eab_handler.allowed_domains_check(csr, value)
        else:
            # execute default adl function from helper
            logger.debug(
                "Helper.eab_profile_list_check(): execute default allowed_domainlist_check()"
            )
            error = allowed_domainlist_check(logger, csr, value)
        if error:
            result = error
    else:
        logger.error(
            "Helper.eab_profile_list_check(): ignore list attribute: key: %s value: %s",
            key,
            value,
        )

    logger.debug("Helper.eab_profile_list_check() ended with: %s", result)
    return result


def eab_profile_string_check(logger, cahandler, key, value):
    """check if a for a string value taken from profile if its a variable inside a class and apply value"""
    logger.debug(
        "Helper.eab_profile_string_check(): string: key: %s, value: %s", key, value
    )

    if hasattr(cahandler, key):
        logger.debug(
            "Helper.eab_profile_string_check(): setting attribute: %s to %s", key, value
        )
        setattr(cahandler, key, value)
    else:
        logger.error(
            "Helper.eab_profile_string_check(): ignore string attribute: key: %s value: %s",
            key,
            value,
        )

    logger.debug("Helper.eab_profile_string_check() ended")


def request_operation(
    logger: logging.Logger,
    headers: Dict[str, str] = None,
    proxy: Dict[str, str] = None,
    timeout: int = 20,
    url: str = None,
    session=requests,
    method: str = "GET",
    payload: Dict[str, str] = None,
):
    """check if a for a string value taken from profile if its a variable inside a class and apply value"""
    logger.debug("Helper.api_operation(): method: %s", method)

    try:
        if method.lower() == "get":
            api_response = session.get(
                url=url, headers=headers, proxies=proxy, timeout=timeout
            )
        elif method.lower() == "post":
            api_response = session.post(
                url=url, headers=headers, proxies=proxy, timeout=timeout, json=payload
            )
        elif method.lower() == "put":
            api_response = session.put(
                url=url, headers=headers, proxies=proxy, timeout=timeout, json=payload
            )
        else:
            logger.error("unknown request method: %s", method)
            api_response = None

        code = api_response.status_code
        if api_response.text:
            try:
                content = api_response.json()
            except Exception as err_:
                logger.error(
                    "request_operation returned error during json parsing: %s", err_
                )
                content = str(err_)
        else:
            content = None

    except Exception as err_:
        logger.error("request_operation returned error: %s", err_)
        code = 500
        content = str(err_)

    logger.debug("Helper.request_operation() ended with: %s", code)
    return code, content


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
            logger.error("no SANs found in CSR")

    logger.debug("Helper._csr_cn_lookup() ended with: %s", csr_cn)
    return csr_cn


def enrollment_config_log(
    logger: logging.Logger, obj: object, handler_skiplist: List[str] = None
):
    """log enrollment configuration"""
    logger.debug("Helper.enrollment_config_log()")

    skiplist = [
        "logger",
        "session",
        "password",
        "api_key",
        "api_password",
        "key",
        "secret",
        "token",
        "err_msg_dic",
        "dbstore",
    ]

    if handler_skiplist and isinstance(handler_skiplist, list):
        skiplist.extend(handler_skiplist)

    if handler_skiplist and PARSING_ERR_MSG in handler_skiplist:
        logger.error(
            "Enrollment configuration won't get logged due to a configuration error."
        )
    else:
        enroll_parameter_list = []
        for key, value in obj.__dict__.items():
            if key.startswith("__") or key in skiplist:
                continue
            enroll_parameter_list.append(f"{key}: {value}")
        logger.info("Enrollment configuration: %s", enroll_parameter_list)


def radomize_parameter_list(
    logger: logging.Logger, ca_handler: object, parameter_list: List[str] = None
):
    """randomize parameter list"""
    logger.debug("Helper.radomize_parameter_list()")

    tmp_dic = {}
    for parameter in parameter_list:
        if hasattr(ca_handler, parameter):
            value = getattr(ca_handler, parameter)
            if value and "," in value:
                values_list = value.split(",")
                tmp_dic[parameter] = []
                for ele in values_list:
                    tmp_dic[parameter].append(ele.strip())

    if tmp_dic:
        # Find the list with the minimum length in tmp_dic values
        min_length_list = min(tmp_dic.values(), key=len)
        # Get the length of that list
        min_len = len(min_length_list)

        # Calculate random number as index for the parameter list
        index = random.randint(0, min_len - 1)
        # set parameter values
        for parameter, value_list in tmp_dic.items():
            setattr(ca_handler, parameter, value_list[index])


def handler_config_check(logger, handler, parameterlist) -> str:
    """check if handler config is valid"""
    logger.debug("CAhandler._config_check()")
    error = None

    error = None
    for ele in parameterlist:
        if not getattr(handler, ele):

            error = f"{ele} parameter is missing in config file"
            logger.error("Configuration check ended with error: %s", error)
            break

    logger.debug("CAhandler._config_check() ended with %s", error)
    return error
