# -*- coding: utf-8 -*-
"""Cryptographic operations for acme2certifier"""
import base64
import hashlib
import json
import logging
import random
import re
from string import digits, ascii_letters
from typing import Dict, Tuple
from jwcrypto import jwk, jws
from .encoding import b64decode_pad, b64_encode
from .validation import dkeys_lower
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
        logger.error("Error during message decoding %s", err)
        error = str(err)
        protected = {}
        payload = {}
        signature = None

    if payload:
        payload = dkeys_lower(payload)
    return (result, error, protected, payload, signature)



def generate_random_string(logger: logging.Logger, length: int) -> str:
    """generate random string to be used as name"""
    logger.debug("Helper.generate_random_string()")
    char_set = digits + ascii_letters
    return "".join(random.choice(char_set) for _ in range(length))



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



