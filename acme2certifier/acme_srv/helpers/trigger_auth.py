# -*- coding: utf-8 -*-
"""Authentication and certificate trust helpers for the /trigger endpoint."""

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
_TRIGGER_SIG_HEADER_ALIASES = frozenset(
    (
        "http-x-a2c-trigger-signature",
        "x-a2c-trigger-signature",
    )
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
        if normalized in _TRIGGER_SIG_HEADER_ALIASES and value:
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


def _trigger_section_present(config_dic: Any) -> bool:
    """True when config_dic exposes a [Trigger] section."""
    has_section = getattr(config_dic, "has_section", None)
    if callable(has_section):
        return bool(has_section("Trigger"))
    if hasattr(config_dic, "__contains__"):
        return "Trigger" in config_dic
    return False


def _trigger_option_get(config_dic: Any, option: str, fallback: Any = None) -> Any:
    """Read a [Trigger] option from ConfigParser or plain dict configs."""
    get = getattr(config_dic, "get", None)
    if not callable(get):
        return fallback
    try:
        return get("Trigger", option, fallback=fallback)
    except TypeError:
        # Plain dict configs (unit tests) do not accept fallback=
        section = config_dic.get("Trigger")
        if isinstance(section, dict):
            return section.get(option, fallback)
        return fallback


def _trigger_parse_hmac_keys_json(logger: logging.Logger, raw_keys: str) -> List[str]:
    """Parse inline [Trigger] hmac_keys JSON list."""
    try:
        parsed = json.loads(raw_keys)
        if not isinstance(parsed, list):
            raise ValueError("hmac_keys must be a JSON list")
        return _normalize_key_list(parsed)
    except Exception as err:
        logger.error("Failed to parse [Trigger] hmac_keys: %s", err)
        return []


def _trigger_load_hmac_keys_file(logger: logging.Logger, keys_file: str) -> List[str]:
    """Load HMAC keys from [Trigger] hmac_keys_file."""
    resolved = resolve_config_path(str(keys_file).strip())
    if not resolved or not os.path.isfile(resolved):
        logger.error(
            "[Trigger] hmac_keys_file %s does not exist or is not a file",
            keys_file,
        )
        return []
    try:
        return _load_keys_from_file(logger, resolved)
    except Exception as err:
        logger.error("Failed to load [Trigger] hmac_keys_file: %s", err)
        return []


def _dedupe_preserve_order(keys: List[str]) -> List[str]:
    """Return keys with duplicates removed, preserving first-seen order."""
    seen: set = set()
    deduped: List[str] = []
    for key in keys:
        if key not in seen:
            seen.add(key)
            deduped.append(key)
    return deduped


def _trigger_auth_disabled_resolve(logger: logging.Logger, config_dic: Any) -> bool:
    """True when auth_disable is set and the security gate is acknowledged."""
    getboolean = getattr(config_dic, "getboolean", None)
    if not callable(getboolean):
        return False
    try:
        auth_disable_requested = bool(
            getboolean("Trigger", "auth_disable", fallback=False)
        )
    except Exception:
        return False

    if not auth_disable_requested:
        return False

    if security_disable_acknowledged():
        logger.critical(
            "**** SECURITY DISABLE ACKNOWLEDGED via %s: [Trigger] auth_disable "
            "is active; /trigger accepts unsigned payloads. Testing only. ****",
            SECURITY_DISABLE_ACK_ENV,
        )
        return True

    logger.warning(
        "[Trigger] auth_disable is set but ignored without %s=1; "
        "HMAC authentication remains required",
        SECURITY_DISABLE_ACK_ENV,
    )
    return False


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
    if not _trigger_section_present(config_dic) or not callable(
        getattr(config_dic, "get", None)
    ):
        return ([], False)

    keys: List[str] = []
    raw_keys = _trigger_option_get(config_dic, "hmac_keys")
    if raw_keys:
        keys.extend(_trigger_parse_hmac_keys_json(logger, raw_keys))

    keys_file = _trigger_option_get(config_dic, "hmac_keys_file")
    if keys_file:
        keys.extend(_trigger_load_hmac_keys_file(logger, keys_file))

    keys = _dedupe_preserve_order(keys)
    auth_disabled = _trigger_auth_disabled_resolve(logger, config_dic)

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
    raw = _trigger_option_get(config_dic, "ca_cert")
    if not raw:
        return None
    resolved = resolve_config_path(str(raw).strip())
    if not resolved or not os.path.isfile(resolved):
        logger.error("[Trigger] ca_cert %s does not exist or is not a file", raw)
        return None
    logger.debug("trigger_auth.trigger_ca_cert_load() ended with: %s", resolved)
    return resolved


def trigger_hmac_verify(body: bytes, signature: Optional[str], keys: List[str]) -> bool:
    """Return True if signature is hex HMAC-SHA256 of body under any key."""
    if not signature or not keys or body is None:
        return False
    try:
        provided = binascii.unhexlify(signature.strip())
    except binascii.Error:
        return False
    for key in keys:
        expected = hmac.new(key.encode("utf-8"), body, hashlib.sha256).digest()
        if hmac.compare_digest(expected, provided):
            return True
    return False


def _cert_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def _pem_to_bytes(pem: Any) -> bytes:
    """Normalize PEM string or bytes to bytes."""
    if isinstance(pem, str):
        return pem.encode("utf-8")
    return pem


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


def _load_leaf_and_trust_certs(
    logger: logging.Logger,
    leaf_pem: str,
    ca_cert_path: str,
) -> Optional[Tuple[x509.Certificate, List[x509.Certificate]]]:
    """Load leaf and trust-anchor PEMs; return None on failure."""
    logger.debug("trigger_auth._load_leaf_and_trust_certs(%s)", ca_cert_path)
    try:
        with open(ca_cert_path, "rb") as handle:
            trust_certs = list(x509.load_pem_x509_certificates(handle.read()))
        leaf = x509.load_pem_x509_certificate(_pem_to_bytes(leaf_pem))
    except Exception as err:
        logger.error("Failed to load leaf or ca_cert for trigger verify: %s", err)
        return None

    if not trust_certs:
        logger.error("No certificates found in [Trigger] ca_cert")
        return None
    return (leaf, trust_certs)


def _bundle_intermediates(
    logger: logging.Logger,
    leaf: x509.Certificate,
    bundle_pem: Optional[str],
) -> List[x509.Certificate]:
    """Parse bundle PEMs, excluding the leaf itself."""
    logger.debug("trigger_auth._bundle_intermediates()")
    if not bundle_pem:
        return []
    try:
        leaf_der = _cert_der(leaf)
        return [
            cert
            for cert in x509.load_pem_x509_certificates(_pem_to_bytes(bundle_pem))
            if _cert_der(cert) != leaf_der
        ]
    except Exception as err:
        logger.warning("Could not parse trigger cert_bundle intermediates: %s", err)
        return []


def _find_issuer_in_pool(
    current: x509.Certificate, pool: List[x509.Certificate]
) -> Optional[x509.Certificate]:
    """Return the first pool certificate that signed ``current``, if any."""
    for candidate in pool:
        if _verify_signed_by(current, candidate):
            return candidate
    return None


def _is_trust_anchor(
    issuer: x509.Certificate, trust_certs: List[x509.Certificate]
) -> bool:
    """True when ``issuer`` matches a configured trust-anchor certificate."""
    issuer_der = _cert_der(issuer)
    return any(_cert_der(trust) == issuer_der for trust in trust_certs)


def _walk_cert_chain_to_trust(
    logger: logging.Logger,
    leaf: x509.Certificate,
    pool: List[x509.Certificate],
    trust_certs: List[x509.Certificate],
) -> bool:
    """Walk issuer links from leaf until a trust anchor is reached."""
    logger.debug("trigger_auth._walk_cert_chain_to_trust()")
    current = leaf
    visited: set = set()
    for _ in range(len(pool) + 1):
        fingerprint = current.fingerprint(hashes.SHA256())
        if fingerprint in visited:
            break
        visited.add(fingerprint)

        issuer = _find_issuer_in_pool(current, pool)
        if issuer is None:
            logger.warning("Trigger cert chain verify failed: no issuer for leaf/cert")
            return False
        if _is_trust_anchor(issuer, trust_certs):
            return True
        current = issuer

    logger.warning("Trigger cert chain verify failed: trust anchor not reached")
    return False


def trigger_cert_chain_verify(
    logger: logging.Logger,
    leaf_pem: str,
    bundle_pem: Optional[str],
    ca_cert_path: str,
) -> bool:
    """Verify leaf chains to a trust anchor in ca_cert_path (multi-PEM allowed)."""
    logger.debug("trigger_auth.trigger_cert_chain_verify(%s)", ca_cert_path)

    loaded = _load_leaf_and_trust_certs(logger, leaf_pem, ca_cert_path)
    if loaded is None:
        return False
    leaf, trust_certs = loaded

    candidates = _bundle_intermediates(logger, leaf, bundle_pem)
    verified = _walk_cert_chain_to_trust(
        logger, leaf, candidates + trust_certs, trust_certs
    )
    if verified:
        logger.debug("trigger_auth.trigger_cert_chain_verify() ended True")
    return verified
