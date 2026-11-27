# -*- coding: utf-8 -*-
"""Cryptographic operations for acme2certifier"""

import hashlib
import json
import logging
import re
import secrets
from string import digits, ascii_letters
from typing import Any, Dict, Optional, Tuple
from jwcrypto import jwk, jws
from .encoding import B64_DECODE_ERROR, b64decode_pad, b64_encode
from .validation import dkeys_lower

# Cached once per process: whether jwcrypto can load kty=AKP (RFC 9964).
_AKP_SUPPORTED: Optional[bool] = None


def akp_jwk_supported(logger) -> bool:
    """Return True if jwcrypto accepts JWK key type AKP on this stack."""
    logger.debug("Helper.akp_jwk_supported()")
    global _AKP_SUPPORTED
    if _AKP_SUPPORTED is None:
        try:
            _AKP_SUPPORTED = "AKP" in jwk.JWKTypesRegistry
        except Exception:
            _AKP_SUPPORTED = False
    logger.debug("Helper.akp_jwk_supported() ended with: %s", _AKP_SUPPORTED)
    return _AKP_SUPPORTED


def unsupported_jwk_detail(logger, pub_key: Any) -> Optional[str]:
    """Return a client-facing detail if this JWK cannot be used on this server.

    Only rejects kty=AKP when the local jwcrypto build has no AKP support
    (typical legacy cryptography/jwcrypto without ML-DSA).
    """
    logger.debug("Helper.unsupported_jwk_detail()")
    if not isinstance(pub_key, dict):
        logger.debug("Helper.unsupported_jwk_detail(): pub_key is not a dict")
        return None
    if pub_key.get("kty") != "AKP":
        logger.debug("Helper.unsupported_jwk_detail(): pub_key.get('kty') != 'AKP'")
        return None
    if akp_jwk_supported(logger):
        logger.debug("Helper.unsupported_jwk_detail(): akp_jwk_supported()")
        return None
    alg = pub_key.get("alg", "unknown")
    logger.debug("Helper.unsupported_jwk_detail(): alg = %s", alg)
    return (
        f'JWK key type "AKP" (alg "{alg}") is not supported by this ACME server'
    )


def decode_deserialize(logger: logging.Logger, string: str) -> Dict:
    """decode and deserialize string"""
    logger.debug("Helper.decode_deserialize()")
    # b64 decode
    string_decode = b64decode_pad(logger, string)
    # deserialize if b64 decoding was successful
    if string_decode and string_decode != B64_DECODE_ERROR:
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
        logger.error("Error during message decoding %s", err)
        error = str(err)
        protected = {}
        payload = {}
        signature = None

    if payload:
        payload = dkeys_lower(payload)
    return (result, error, protected, payload, signature)


def generate_random_string(logger: logging.Logger, length: int) -> str:
    """generate cryptographically secure random string to be used as name"""
    logger.debug("Helper.generate_random_string()")
    char_set = digits + ascii_letters
    return "".join(secrets.choice(char_set) for _ in range(length))


def jwk_thumbprint_get(logger: logging.Logger, pub_key: Dict[str, str]) -> str:
    """get thumbprint"""
    logger.debug("Helper.jwk_thumbprint_get()")
    if pub_key:
        try:
            jwkey = jwk.JWK(**pub_key)
            thumbprint = jwkey.thumbprint()
        except Exception as err:
            logger.error("Could not get the JWKEY thumbprint from public key: %s", err)
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
    logger: logging.Logger, message: str, pub_key: Any, json_: bool = False
) -> Tuple[bool, Optional[str]]:
    """check JWS"""
    logger.debug("Helper.signature_check(%s)", json_)

    result = False
    error = None

    if pub_key:
        # Reject unsupported AKP before jwcrypto raises Unknown type "AKP".
        # Skip EAB (json_=True): that path uses an oct MAC key, not an account JWK.
        if not json_:
            detail = unsupported_jwk_detail(logger, pub_key)
            if detail:
                logger.error("%s", detail)
                return (False, detail)

        # load key
        try:
            if json_:
                logger.debug("Helper.signature_check(): load key from json")
                jwkey = jwk.JWK.from_json(pub_key)
            else:
                logger.debug("Helper.signature_check(): load plain json")
                jwkey = jwk.JWK(**pub_key)
        except Exception as err:
            logger.error("Loading of public key failed %s", err)
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
                logger.error("Message verification failed %s", err)
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
