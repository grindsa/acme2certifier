# -*- coding: utf-8 -*-
"""Domain utilities for acme2certifier"""
import re
import logging
from typing import List, Tuple
import idna
from .csr import csr_san_get, csr_cn_get

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

        # clean email addresses
        tmp_san_list = []
        for san in san_list:
            if "@" in san:
                _email_name, email_domain = san.split("@", 1)
                tmp_san_list.append(email_domain)
            else:
                tmp_san_list.append(san)
        san_list = tmp_san_list

        invalid_domains = []

        # go over the san list and check each entry
        for san in san_list:
            if not is_domain_whitelisted(logger, san, allowed_domain_list):
                invalid_domains.append(san)
                error = "Either CN or SANs are not allowed by configuration"

        if check_list:
            error = f"SAN list parsing failed {check_list}"

        logger.debug(
            f'Helper.allowed_domainlist_check() ended with {error} for {",".join(invalid_domains)}'
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




