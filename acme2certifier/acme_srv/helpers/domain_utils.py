# -*- coding: utf-8 -*-
"""Domain utilities for acme2certifier"""

import logging
from typing import List, Optional, Tuple
import idna
from .csr import csr_san_get, csr_cn_get
from .validation import validate_ip, validate_network


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


def is_ip_whitelisted(logger, ip_address, ip_network_list):
    """check if an ip address is in a list of ip networks"""
    logger.debug("Helper.is_ip_whitelisted(%s, %s)", ip_address, ip_network_list)
    try:
        ip = validate_ip(logger, ip_address, raw=True)
    except ValueError:
        return False

    for net_str in ip_network_list:
        try:
            network = validate_network(logger, net_str)
        except ValueError:
            logger.error(f"Invalid network entry in allowed_iplist: {net_str}")
            continue  # Ignore invalid network entries
        if ip in network:
            return True

    return False


def is_email_whitelisted(logger, email_address, email_list):
    """Check if an email address is in a list of allowed email addresses or wildcard patterns.

    Supports exact matches and wildcard patterns like *@example.com.
    """
    logger.debug("Helper.is_email_whitelisted(%s, %s)", email_address, email_list)
    email_address = email_address.lower().strip()
    for pattern in email_list:
        pattern = pattern.lower().strip()
        if pattern == email_address:
            return True
        # Support wildcard pattern: *@example.com
        if pattern.startswith("*@"):
            domain_part = pattern[2:]
            if email_address.endswith("@" + domain_part):
                return True
    return False


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


def is_single_label_name(logger: logging.Logger, name: str) -> bool:
    """Return True if name is a single DNS label (no dots, no wildcards)."""
    logger.debug("Helper.is_single_label_name(%s)", name)
    result = False
    if name:
        normalized = name.lower().strip()
        if normalized and "." not in normalized and "*" not in normalized:
            result = True
    logger.debug("Helper.is_single_label_name() ended with %s", result)
    return result


def is_shortname_denied(
    logger: logging.Logger, name: str, shortname_denylist: List[str]
) -> bool:
    """Return True if name matches an entry on the shortname denylist (case-insensitive)."""
    logger.debug("Helper.is_shortname_denied(%s)", name)
    result = False
    if name and shortname_denylist:
        normalized = name.lower().strip()
        for entry in shortname_denylist:
            if entry and entry.lower().strip() == normalized:
                result = True
                break
    logger.debug("Helper.is_shortname_denied() ended with %s", result)
    return result


def _is_covering_fqdn_sibling(logger: logging.Logger, sibling: str) -> bool:
    """True if sibling is a multi-label non-wildcard DNS name (not an IP)."""
    logger.debug("Helper._is_covering_fqdn_sibling(%s)", sibling)
    result = False
    if sibling:
        normalized = sibling.lower().strip()
        if (
            normalized
            and not normalized.startswith("*.")
            and "*" not in normalized
            and "." in normalized
        ):
            try:
                validate_ip(logger, normalized, raw=True)
                result = False
            except ValueError:
                result = True
    logger.debug("Helper._is_covering_fqdn_sibling() ended with %s", result)
    return result


def shortname_covered_by_siblings(
    logger: logging.Logger,
    shortname: str,
    sibling_names: List[str],
    allowed_domainlist: List[str],
) -> bool:
    """True if an allowed multi-label sibling FQDN has first label equal to shortname."""
    logger.debug(
        "Helper.shortname_covered_by_siblings(%s, siblings=%s)",
        shortname,
        sibling_names,
    )
    if not is_single_label_name(logger, shortname):
        logger.debug("Helper.shortname_covered_by_siblings() ended with False")
        return False

    short = shortname.lower().strip()
    for sibling in sibling_names or []:
        if not _is_covering_fqdn_sibling(logger, sibling):
            continue
        sibling_norm = sibling.lower().strip()
        if sibling_norm.split(".", 1)[0] != short:
            continue
        if is_domain_whitelisted(logger, sibling_norm, allowed_domainlist):
            logger.debug(
                "Helper.shortname_covered_by_siblings() ended with True (sibling=%s)",
                sibling_norm,
            )
            return True

    logger.debug("Helper.shortname_covered_by_siblings() ended with False")
    return False


def allowed_domainlist_check(
    logger: logging.Logger,
    csr,
    allowed_domain_list: List[str],
    allow_shortname_from_fqdn: bool = False,
    shortname_denylist: Optional[List[str]] = None,
) -> str:
    """check if domain is in allowed domain list"""
    logger.debug(
        "Helper.allowed_domainlist_check(allow_shortname_from_fqdn=%s)",
        allow_shortname_from_fqdn,
    )

    error = None
    if allowed_domain_list:
        san_list, check_list = sancheck_lists_create(logger, csr)

        # clean email addresses
        tmp_san_list = []
        for san in san_list:
            if "@" in san:
                _email_name, email_domain = san.split("@", 1)
                tmp_san_list.append(email_domain)
            else:
                tmp_san_list.append(san)
        san_list = tmp_san_list

        denylist = shortname_denylist or []
        invalid_domains = []

        # go over the san list and check each entry
        for san in san_list:
            if is_domain_whitelisted(logger, san, allowed_domain_list):
                continue
            if (
                allow_shortname_from_fqdn
                and is_single_label_name(logger, san)
                and not is_shortname_denied(logger, san, denylist)
                and shortname_covered_by_siblings(
                    logger, san, san_list, allowed_domain_list
                )
            ):
                continue
            invalid_domains.append(san)
            error = "Either CN or SANs are not allowed by configuration"

        if check_list:
            error = f"SAN list parsing failed {check_list}"

        logger.debug(
            f'Helper.allowed_domainlist_check() ended with {error} for {",".join(invalid_domains)}'
        )
    return error


def sancheck_lists_create(
    logger, csr: str, include_cn: bool = True
) -> Tuple[List[str], List[str]]:
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
                _san_type, san_value = san.lower().split(":")
                san_list.append(san_value)
            except Exception:
                # force check to fail as something went wrong during parsing
                check_list.append(san)
                logger.debug(
                    "Helper.sancheck_lists_create(): san_list parsing failed at entry: %s",
                    san,
                )

    if include_cn:
        # get common name and attach it to san_list
        cn = csr_cn_get(logger, csr)

        if cn:
            cn = cn.lower()
            if cn not in san_list:
                # append cn to san_list
                logger.debug("Helper.sancheck_lists_create()): append cn to san_list")
                san_list.append(cn)

    return (san_list, check_list)
