# -*- coding: utf-8 -*-
"""Validation utilities for acme2certifier"""
import re
import logging
import ipaddress
from typing import List, Dict, Tuple


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
                logger.error("Error during SAN check. SAN split failed: %s", san)

    logger.debug("Helper.fqdn_in_san_check() ended with: %s", result)
    return result


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
    """validate identifier format"""
    logger.debug("Helper.validate_identifier()")

    result = False
    if identifier:
        if id_type == "dns":
            result = validate_fqdn(logger, identifier)
        elif id_type == "ip":
            result = validate_ip(logger, identifier)
        elif id_type == "email":
            result = validate_email(logger, [identifier])
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
