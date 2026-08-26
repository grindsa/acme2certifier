# -*- coding: utf-8 -*-
"""Authentication and certificate trust helpers for the /trigger endpoint."""

from __future__ import annotations

import binascii
import hashlib
import hmac
import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from .config import resolve_config_path
from .security_gate import SECURITY_DISABLE_ACK_ENV, security_disable_acknowledged

TRIGGER_SIGNATURE_HEADER = "X-A2C-Trigger-Signature"
_TRIGGER_SIG_META_KEYS = (
    "HTTP_X_A2C_TRIGGER_SIGNATURE",
    "X-A2C-Trigger-Signature",
    "x-a2c-trigger-signature",
)


def trigger_signature_from_headers(headers: Optional[Dict[str, Any]]) -> Optional[str]:
    """Extract the trigger HMAC header from WSGI environ or Django META."""
    if not headers:
        return None
    for key in _TRIGGER_SIG_META_KEYS:
        value = headers.get(key)
        if value:
            return str(value).strip()
    for key, value in headers.items():
        normalized = str(key).lower().replace("_", "-")
        if normalized in {
            "http-x-a2c-trigger-signature",
            "x-a2c-trigger-signature",
        }:
            if value:
                return str(value).strip()
    return None


def _normalize_key_list(raw_keys: List[Any]) -> List[str]:
    keys: List[str] = []
    for item in raw_keys:
        if item is None:
            continue
        text = str(item).strip()
        if text:
            keys.append(text)
    return keys


def _load_keys_from_file(logger: logging.Logger, path: str) -> List[str]:
    logger.debug("trigger_auth._load_keys_from_file(%s)", path)
    with open(path, "r", encoding="utf-8") as handle:
        content = handle.read()
    stripped = content.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        parsed = json.loads(stripped)
        if not isinstance(parsed, list):
            raise ValueError("hmac_keys_file JSON must be a list")
        return _normalize_key_list(parsed)
    keys: List[str] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        keys.append(line)
    return keys


def trigger_hmac_keys_load(
    logger: logging.Logger, config_dic: Any
) -> Tuple[List[str], bool]:
    """Load HMAC keys and auth_disable (gated) from [Trigger].

    Returns:
        (hmac_keys, auth_disabled)
        auth_disabled is True only when auth_disable is set and the security gate
        is acknowledged.
    """
    logger.debug("trigger_auth.trigger_hmac_keys_load()")
    keys: List[str] = []
    auth_disabled = False

    get = getattr(config_dic, "get", None)
    getboolean = getattr(config_dic, "getboolean", None)
    has_section = getattr(config_dic, "has_section", None)
    has_trigger = False
    if callable(has_section):
        has_trigger = bool(has_section("Trigger"))
    elif hasattr(config_dic, "__contains__"):
        has_trigger = "Trigger" in config_dic
    if not has_trigger or not callable(get):
        return ([], False)

    try:
        raw_keys = get("Trigger", "hmac_keys", fallback=None)
    except TypeError:
        # Plain dict configs (unit tests) do not accept fallback=
        section = config_dic.get("Trigger") if callable(get) else None
        raw_keys = section.get("hmac_keys") if isinstance(section, dict) else None
    if raw_keys:
        try:
            parsed = json.loads(raw_keys)
            if not isinstance(parsed, list):
                raise ValueError("hmac_keys must be a JSON list")
            keys.extend(_normalize_key_list(parsed))
        except Exception as err:
            logger.error("Failed to parse [Trigger] hmac_keys: %s", err)

    try:
        keys_file = get("Trigger", "hmac_keys_file", fallback=None)
    except TypeError:
        section = config_dic.get("Trigger") if callable(get) else None
        keys_file = (
            section.get("hmac_keys_file") if isinstance(section, dict) else None
        )
    if keys_file:
        resolved = resolve_config_path(str(keys_file).strip())
        if not resolved or not os.path.isfile(resolved):
            logger.error(
                "[Trigger] hmac_keys_file %s does not exist or is not a file",
                keys_file,
            )
        else:
            try:
                keys.extend(_load_keys_from_file(logger, resolved))
            except Exception as err:
                logger.error("Failed to load [Trigger] hmac_keys_file: %s", err)

    seen = set()
    deduped: List[str] = []
    for key in keys:
        if key not in seen:
            seen.add(key)
            deduped.append(key)
    keys = deduped

    auth_disable_requested = False
    if callable(getboolean):
        try:
            auth_disable_requested = bool(
                getboolean("Trigger", "auth_disable", fallback=False)
            )
        except Exception:
            auth_disable_requested = False

    if auth_disable_requested:
        if security_disable_acknowledged():
            auth_disabled = True
            logger.critical(
                "**** SECURITY DISABLE ACKNOWLEDGED via %s: [Trigger] auth_disable "
                "is active; /trigger accepts unsigned payloads. Testing only. ****",
                SECURITY_DISABLE_ACK_ENV,
            )
        else:
            logger.warning(
                "[Trigger] auth_disable is set but ignored without %s=1; "
                "HMAC authentication remains required",
                SECURITY_DISABLE_ACK_ENV,
            )

    logger.debug(
        "trigger_auth.trigger_hmac_keys_load() ended keys=%s auth_disabled=%s",
        len(keys),
        auth_disabled,
    )
    return (keys, auth_disabled)


def trigger_ca_cert_load(logger: logging.Logger, config_dic: Any) -> Optional[str]:
    """Resolve [Trigger] ca_cert to an absolute existing file path, or None."""
    logger.debug("trigger_auth.trigger_ca_cert_load()")
    get = getattr(config_dic, "get", None)
    if not callable(get):
        return None
    try:
        raw = get("Trigger", "ca_cert", fallback=None)
    except TypeError:
        section = get("Trigger")
        raw = section.get("ca_cert") if isinstance(section, dict) else None
    if not raw:
        return None
    resolved = resolve_config_path(str(raw).strip())
    if not resolved or not os.path.isfile(resolved):
        logger.error("[Trigger] ca_cert %s does not exist or is not a file", raw)
        return None
    logger.debug("trigger_auth.trigger_ca_cert_load() ended with: %s", resolved)
    return resolved


def trigger_hmac_verify(
    body: bytes, signature: Optional[str], keys: List[str]
) -> bool:
    """Return True if signature is hex HMAC-SHA256 of body under any key."""
    if not signature or not keys or body is None:
        return False
    try:
        provided = binascii.unhexlify(signature.strip())
    except (binascii.Error, ValueError):
        return False
    for key in keys:
        expected = hmac.new(key.encode("utf-8"), body, hashlib.sha256).digest()
        if hmac.compare_digest(expected, provided):
            return True
    return False


def _cert_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def _verify_signed_by(leaf: x509.Certificate, issuer: x509.Certificate) -> bool:
    if leaf.issuer != issuer.subject:
        return False
    public_key = issuer.public_key()
    hash_alg = leaf.signature_hash_algorithm
    if hash_alg is None:
        return False
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                leaf.signature,
                leaf.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hash_alg,
            )
            return True
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                leaf.signature,
                leaf.tbs_certificate_bytes,
                ec.ECDSA(hash_alg),
            )
            return True
    except Exception:
        return False
    return False


def trigger_cert_chain_verify(
    logger: logging.Logger,
    leaf_pem: str,
    bundle_pem: Optional[str],
    ca_cert_path: str,
) -> bool:
    """Verify leaf chains to a trust anchor in ca_cert_path (multi-PEM allowed)."""
    logger.debug("trigger_auth.trigger_cert_chain_verify(%s)", ca_cert_path)
    try:
        with open(ca_cert_path, "rb") as handle:
            trust_certs = list(x509.load_pem_x509_certificates(handle.read()))
        leaf_bytes = (
            leaf_pem.encode("utf-8") if isinstance(leaf_pem, str) else leaf_pem
        )
        leaf = x509.load_pem_x509_certificate(leaf_bytes)
    except Exception as err:
        logger.error("Failed to load leaf or ca_cert for trigger verify: %s", err)
        return False

    if not trust_certs:
        logger.error("No certificates found in [Trigger] ca_cert")
        return False

    candidates: List[x509.Certificate] = []
    if bundle_pem:
        try:
            bundle_bytes = (
                bundle_pem.encode("utf-8")
                if isinstance(bundle_pem, str)
                else bundle_pem
            )
            leaf_der = _cert_der(leaf)
            for cert in x509.load_pem_x509_certificates(bundle_bytes):
                if _cert_der(cert) != leaf_der:
                    candidates.append(cert)
        except Exception as err:
            logger.warning("Could not parse trigger cert_bundle intermediates: %s", err)

    pool = candidates + trust_certs
    current = leaf
    visited = set()
    for _ in range(len(pool) + 1):
        fingerprint = current.fingerprint(hashes.SHA256())
        if fingerprint in visited:
            break
        visited.add(fingerprint)

        issuer = None
        for candidate in pool:
            if _verify_signed_by(current, candidate):
                issuer = candidate
                break
        if issuer is None:
            logger.warning("Trigger cert chain verify failed: no issuer for leaf/cert")
            return False

        issuer_der = _cert_der(issuer)
        for trust in trust_certs:
            if _cert_der(trust) == issuer_der:
                logger.debug("trigger_auth.trigger_cert_chain_verify() ended True")
                return True
        current = issuer

    logger.warning("Trigger cert chain verify failed: trust anchor not reached")
    return False
