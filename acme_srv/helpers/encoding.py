# -*- coding: utf-8 -*-
"""Encoding and base64 utilities for acme2certifier"""
import base64
import textwrap
import logging


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
