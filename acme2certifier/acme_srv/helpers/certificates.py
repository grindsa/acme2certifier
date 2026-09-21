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
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed25519,
    ed448,
    padding,
    rsa,
)
from .encoding import (
    convert_string_to_byte,
    convert_byte_to_string,
    build_pem_file,
    b64_url_recode,
    b64_decode,
)
from .datetime_utils import date_to_uts_utc
from .global_variables import CONFIGURATION_ERROR_DETAIL
from pyasn1.codec.der import decoder
from pyasn1.type import univ
from pyasn1_modules import rfc5280

_OID_SKI = "2.5.29.14"
_OID_AKI = "2.5.29.35"


# #region agent log
def _agent_dbg(hypothesis_id: str, location: str, message: str, data: dict) -> None:
    """Session debug ingest for cert-chain rewrite troubleshooting."""
    import json
    import time

    try:
        with open(
            "/Users/jm/Development/acme2certifier/.cursor/debug-274d4c.log",
            "a",
            encoding="utf-8",
        ) as handle:
            handle.write(
                json.dumps(
                    {
                        "sessionId": "274d4c",
                        "timestamp": int(time.time() * 1000),
                        "hypothesisId": hypothesis_id,
                        "location": location,
                        "message": message,
                        "data": data,
                    }
                )
                + "\n"
            )
    except Exception:
        pass


def _cert_dbg_info(cert: x509.Certificate) -> dict:
    """Subject/issuer/fingerprint summary (no key material)."""
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "fp": _cert_sha256_fingerprint(cert),
        "self_signed": cert.subject == cert.issuer,
        "key_type": type(cert.public_key()).__name__,
    }


# #endregion


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


def _cert_sha256_fingerprint(cert: x509.Certificate) -> str:
    """SHA-256 fingerprint as lowercase hex (no colons)."""
    return cert.fingerprint(hashes.SHA256()).hex()


def _pem_fingerprint(
    logger: logging.Logger, pem_cert: str
) -> Tuple[Optional[str], Optional[str]]:
    """Return ``(error, fingerprint)`` for a single PEM certificate."""
    try:
        cert = cert_load(logger, pem_cert, recode=False)
    except Exception as err_:
        logger.error("Failed to parse certificate in chain: %s", err_)
        return (
            f"{CONFIGURATION_ERROR_DETAIL}: Failed to parse certificate chain",
            None,
        )
    return None, _cert_sha256_fingerprint(cert)


def cert_chain_skip(
    logger: logging.Logger,
    pem_bundle: Optional[str],
    skip_list: Optional[List[str]],
) -> Tuple[Optional[str], Optional[str]]:
    """Drop certificates whose SHA-256 fingerprint is in *skip_list*."""
    logger.debug("Helper.cert_chain_skip()")
    if not pem_bundle:
        logger.debug("Helper.cert_chain_skip() ended (empty bundle)")
        return None, pem_bundle
    if not skip_list:
        logger.debug("Helper.cert_chain_skip() ended (skip list empty)")
        return None, pem_bundle

    pem_list = pembundle_to_list(logger, pem_bundle)
    if not pem_list:
        logger.error("cert_chain_skip_list is set but the bundle is not a PEM chain")
        return (
            f"{CONFIGURATION_ERROR_DETAIL}: Failed to parse certificate chain",
            None,
        )

    skip_set = set(skip_list)
    error, leaf_fp = _pem_fingerprint(logger, pem_list[0])
    if error:
        return error, None
    if leaf_fp in skip_set:
        logger.error("cert_chain_skip_list must not include the end-entity certificate")
        return (
            f"{CONFIGURATION_ERROR_DETAIL}: "
            "cert_chain_skip_list includes the end-entity certificate",
            None,
        )

    kept = [pem_list[0]]
    for pem_cert in pem_list[1:]:
        error, fingerprint = _pem_fingerprint(logger, pem_cert)
        if error:
            return error, None
        if fingerprint not in skip_set:
            kept.append(pem_cert)

    result = "".join(kept)
    logger.debug(
        "Helper.cert_chain_skip() ended with %d of %d certificates kept",
        len(kept),
        len(pem_list),
    )
    # #region agent log
    remaining = []
    for pem_cert in kept:
        try:
            remaining.append(_cert_dbg_info(cert_load(logger, pem_cert, recode=False)))
        except Exception as err_:
            remaining.append({"parse_error": str(err_)})
    _agent_dbg(
        "H1",
        "certificates.py:cert_chain_skip",
        "skip remaining chain",
        {
            "skip_list": list(skip_set),
            "input_count": len(pem_list),
            "kept_count": len(kept),
            "remaining": remaining,
        },
    )
    # #endregion
    return None, result


def _cert_certifies(issuer: x509.Certificate, subject: x509.Certificate) -> bool:
    """Return True when *issuer* signed *subject* (RFC 8555 chain link)."""
    if subject.issuer != issuer.subject:
        return False
    public_key = issuer.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            hash_alg = subject.signature_hash_algorithm
            if hash_alg is None:
                return False
            public_key.verify(
                subject.signature,
                subject.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hash_alg,
            )
            return True
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            hash_alg = subject.signature_hash_algorithm
            if hash_alg is None:
                return False
            public_key.verify(
                subject.signature,
                subject.tbs_certificate_bytes,
                ec.ECDSA(hash_alg),
            )
            return True
        if isinstance(public_key, dsa.DSAPublicKey):
            hash_alg = subject.signature_hash_algorithm
            if hash_alg is None:
                return False
            public_key.verify(
                subject.signature, subject.tbs_certificate_bytes, hash_alg
            )
            return True
        if isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(subject.signature, subject.tbs_certificate_bytes)
            return True
    except Exception:
        return False
    return False


def _certs_from_pems(
    logger: logging.Logger, pem_list: List[str]
) -> Tuple[Optional[str], List[x509.Certificate]]:
    """Load PEM strings with ``cert_load()``. Fail closed on parse errors."""
    certs: List[x509.Certificate] = []
    for pem_cert in pem_list:
        try:
            certs.append(cert_load(logger, pem_cert, recode=False))
        except Exception as err_:
            logger.error("Failed to parse certificate in chain: %s", err_)
            return (
                f"{CONFIGURATION_ERROR_DETAIL}: Failed to parse certificate chain",
                [],
            )
    return None, certs


def _parse_pem_bundle(
    logger: logging.Logger, pem_bundle: str
) -> Tuple[Optional[str], List[str], List[x509.Certificate]]:
    """Split *pem_bundle* and load each PEM. Fail closed on an empty or invalid chain."""
    pems = pembundle_to_list(logger, pem_bundle)
    if not pems:
        logger.error("cert_chain_append is set but the bundle is not a PEM chain")
        return (
            f"{CONFIGURATION_ERROR_DETAIL}: Failed to parse certificate chain",
            [],
            [],
        )
    error, certs = _certs_from_pems(logger, pems)
    if error:
        return error, [], []
    return None, pems, certs


def _append_entry_check(
    logger: logging.Logger,
    cert: x509.Certificate,
    leaf_fp: str,
    seen_fps: Set[str],
) -> Tuple[Optional[str], Optional[str]]:
    """Return ``(error, fingerprint)``. Fingerprint is set only when the cert may be appended."""
    logger.debug("Helper._append_entry_check()")
    fingerprint = _cert_sha256_fingerprint(cert)
    if fingerprint == leaf_fp:
        logger.error("cert_chain_append must not include the end-entity certificate")
        return (
            f"{CONFIGURATION_ERROR_DETAIL}: "
            "cert_chain_append includes the end-entity certificate",
            None,
        )
    if fingerprint in seen_fps:
        logger.error("cert_chain_append includes a certificate already in the chain")
        return (
            f"{CONFIGURATION_ERROR_DETAIL}: "
            "cert_chain_append includes a certificate already in the chain",
            None,
        )
    logger.debug("Helper._append_entry_check() ended")
    return None, fingerprint


def _chain_links_error(
    logger: logging.Logger,
    certs: List[x509.Certificate],
    start: int,
    *,
    link_check: bool = True,
) -> Optional[str]:
    """Fail if any certificate from *start* does not certify the previous one."""
    logger.debug("Helper._chain_links_error()")
    for idx in range(start, len(certs) - 1):
        prev = certs[idx]
        nxt = certs[idx + 1]
        issuer_name_match = prev.issuer == nxt.subject
        certifies = _cert_certifies(nxt, prev)
        # #region agent log
        _agent_dbg(
            "H2",
            "certificates.py:_chain_links_error",
            "append link check",
            {
                "idx": idx,
                "prev": _cert_dbg_info(prev),
                "next": _cert_dbg_info(nxt),
                "issuer_name_match": issuer_name_match,
                "certifies": certifies,
                "link_check": link_check,
            },
        )
        # #endregion
        if not certifies:
            if issuer_name_match:
                reason = "issuer name matches but signature verification failed"
            else:
                reason = (
                    f"previous issuer {prev.issuer.rfc4514_string()} != "
                    f"appended subject {nxt.subject.rfc4514_string()}"
                )
            if not link_check:
                logger.warning(
                    "cert_chain_link_check is False; appending a certificate "
                    "that does not certify the previous one (%s)",
                    reason,
                )
                continue
            logger.error(
                "cert_chain_append: certificate %d does not certify the previous one (%s)",
                idx + 1,
                reason,
            )
            return (
                f"{CONFIGURATION_ERROR_DETAIL}: "
                "cert_chain_append certificate does not certify the previous one "
                f"({reason})"
            )
    logger.debug("Helper._chain_links_error() ended")
    return None


def _extend_chain(
    logger: logging.Logger,
    pems: List[str],
    certs: List[x509.Certificate],
    pem_list: List[str],
    *,
    link_check: bool = True,
) -> Optional[str]:
    """Parse *pem_list*, reject leaf/duplicates, append in place, check RFC 8555 links."""
    logger.debug("Helper._extend_chain()")

    join_at = len(certs) - 1
    leaf_fp = _cert_sha256_fingerprint(certs[0])
    seen_fps = {_cert_sha256_fingerprint(cert) for cert in certs}
    error, appended = _certs_from_pems(logger, pem_list)
    if error:
        return error
    for pem_cert, parsed in zip(pem_list, appended):
        error, fingerprint = _append_entry_check(logger, parsed, leaf_fp, seen_fps)
        if error:
            return error
        seen_fps.add(fingerprint)
        pems.append(pem_cert)
        certs.append(parsed)

    logger.debug("Helper._extend_chain() ended with: %s", pems)
    # #region agent log
    _agent_dbg(
        "H4",
        "certificates.py:_extend_chain",
        "append candidates",
        {
            "join_at": join_at,
            "remaining": [_cert_dbg_info(cert) for cert in certs[: join_at + 1]],
            "appended": [_cert_dbg_info(cert) for cert in appended],
        },
    )
    # #endregion
    return _chain_links_error(logger, certs, join_at, link_check=link_check)


def cert_chain_append(
    logger: logging.Logger,
    pem_bundle: Optional[str],
    pem_list: Optional[List[str]],
    *,
    link_check: bool = True,
) -> Tuple[Optional[str], Optional[str]]:
    """Append PEM certificates to *pem_bundle* and check RFC 8555 chain links."""
    logger.debug("Helper.cert_chain_append()")

    if not pem_bundle:
        logger.debug("Helper.cert_chain_append() ended (empty bundle)")
        return None, pem_bundle
    if not pem_list:
        logger.debug("Helper.cert_chain_append() ended (append list empty)")
        return None, pem_bundle

    error, pems, certs = _parse_pem_bundle(logger, pem_bundle)
    if error:
        return error, None

    error = _extend_chain(logger, pems, certs, pem_list, link_check=link_check)
    if error:
        return error, None

    result = "".join(pems)
    logger.debug(
        "Helper.cert_chain_append() ended with %d certificates",
        len(pems),
    )
    logger.debug("Helper.cert_chain_append() ended with: %s", result)
    return None, result


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
