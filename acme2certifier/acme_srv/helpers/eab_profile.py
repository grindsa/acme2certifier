# -*- coding: utf-8 -*-
"""Shared EAB profile helpers: SAN/CN whitelist checks and kid/profile lookup."""

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from .csr import csr_cn_get
from .domain_utils import sancheck_lists_create

ProfileResult = Union[str, bool]


def chk_san_lists_get(logger: logging.Logger, csr: str) -> Tuple[List[str], List[bool]]:
    """Parse CSR SANs; failed entries become False in the check list."""
    logger.debug("EABhandler._chk_san_lists_get()")
    san_list, parse_failures = sancheck_lists_create(logger, csr, include_cn=False)
    check_list = [False for _ in parse_failures]
    logger.debug("EABhandler._chk_san_lists_get() ended")
    return (san_list, check_list)


def cn_add(logger: logging.Logger, csr: str, san_list: List[str]) -> List[str]:
    """Append the CSR CN to san_list when it is missing."""
    logger.debug("EABhandler._cn_add()")
    cn_ = csr_cn_get(logger, csr)
    if cn_:
        cn_ = cn_.lower()
        if cn_ not in san_list:
            logger.debug("EABhandler._csr_check(): append cn to san_list")
            san_list.append(cn_)
    logger.debug("EABhandler._cn_add() ended")
    return san_list


def list_regex_check(logger: logging.Logger, entry: str, list_: List[str]) -> bool:
    """Return True if entry matches any regex in list_."""
    logger.debug("EABhandler._list_regex_check()")
    check_result = False
    for regex in list_:
        if regex.startswith("*."):
            regex = regex.replace("*.", ".")
        regex_compiled = re.compile(regex)
        if bool(regex_compiled.search(entry)):
            check_result = True
            break
    logger.debug("EABhandler._list_regex_check() ended with: %s", check_result)
    return check_result


def wllist_check(
    logger: logging.Logger,
    entry: str,
    list_: List[str],
    toggle: bool = False,
) -> bool:
    """Check entry against a whitelist (toggle=True inverts for a blocklist)."""
    logger.debug("EABhandler._wllist_check(%s:%s)", entry, toggle)
    logger.debug("check against list: %s", list_)
    check_result = False
    if entry:
        if list_:
            check_result = list_regex_check(logger, entry, list_)
        else:
            check_result = True
    if toggle:
        check_result = not check_result
    logger.debug("EABhandler._wllist_check() ended with: %s", check_result)
    return check_result


def eab_profile_entry_normalize(entry: Any) -> Dict[str, Any]:
    """Lowercase top-level keys of a kid profile entry.

    Makes section titles case-insensitive (``Order`` / ``Cahandler`` /
    ``Challenge`` / ``Authorization`` / ``HMAC`` → lowercase). Nested keys
    inside those sections are left unchanged. Kid identifiers in a multi-kid
    map are not modified; call :func:`eab_profiles_normalize` for that.
    """
    if isinstance(entry, str):
        try:
            entry = json.loads(entry)
        except Exception:
            return {}
    if not isinstance(entry, dict):
        return {}
    return {str(key).lower(): value for key, value in entry.items()}


def eab_profile_kid_entry_get(
    profiles_dic: Any, eab_kid: Optional[str]
) -> Dict[str, Any]:
    """Return one kid's profile entry with section titles lowercased.

    Used when applying EAB profiles so handlers can store ``Order`` /
    ``Cahandler`` / etc. without each backend normalizing on load.
    """
    if not eab_kid or not isinstance(profiles_dic, dict) or eab_kid not in profiles_dic:
        return {}
    return eab_profile_entry_normalize(profiles_dic.get(eab_kid))


def eab_profiles_normalize(profiles_dic: Any) -> Dict[str, Any]:
    """Normalize every kid profile entry in a ``kid -> profile`` mapping."""
    if not isinstance(profiles_dic, dict):
        return {}
    normalized: Dict[str, Any] = {}
    for kid, entry in profiles_dic.items():
        if isinstance(entry, dict) or (
            isinstance(entry, str) and entry.strip().startswith("{")
        ):
            normalized[kid] = eab_profile_entry_normalize(entry)
        else:
            normalized[kid] = entry
    return normalized


def _profile_entry_as_dict(entry: Any) -> Dict[str, Any]:
    """Normalize a per-kid profile value (dict or JSON string) to a dict."""
    return eab_profile_entry_normalize(entry)


class EabProfileMixin:
    """SAN/CN profile checks and kid/profile lookup shared by EAB handlers."""

    logger: logging.Logger

    def key_file_load(self) -> Dict[str, Any]:
        """Load kid -> profile mappings. Subclasses implement storage."""
        raise NotImplementedError

    def _chk_san_lists_get(self, csr: str) -> Tuple[List[str], List[bool]]:
        """Parse CSR SAN lists for profile checks."""
        return chk_san_lists_get(self.logger, csr)

    def _cn_add(self, csr: str, san_list: List[str]) -> List[str]:
        """Add CN to SAN list if required."""
        return cn_add(self.logger, csr, san_list)

    def _list_regex_check(self, entry: str, list_: List[str]) -> bool:
        """Check entry against regex list."""
        return list_regex_check(self.logger, entry, list_)

    def _wllist_check(self, entry: str, list_: List[str], toggle: bool = False) -> bool:
        """Check string against list."""
        return wllist_check(self.logger, entry, list_, toggle)

    def _allowed_domains_check(self, csr: str, domain_list: List[str]) -> ProfileResult:
        """Check CN/SANs against an EAB profile domain list."""
        self.logger.debug("EABhandler.allowed_domains_check()")
        san_list, check_list = self._chk_san_lists_get(csr)
        san_list = self._cn_add(csr, san_list)
        for san in san_list:
            check_list.append(self._wllist_check(san, domain_list))
        if check_list:
            if False in check_list:
                result: ProfileResult = "Either CN or SANs are not allowed by profile"
            else:
                result = False
        self.logger.debug("EABhandler.allowed_domains_check() ended with: %s", result)
        return result

    def eab_kid_get(self, csr: str, revocation: bool = False) -> Optional[str]:
        """Look up eab_kid from the certificate store based on csr or cert_raw."""
        self.logger.debug("EABhandler.eab_kid_get()")
        try:
            from acme2certifier.acme_srv.db_handler import (  # pylint: disable=c0415
                DBstore,
            )

            search_key = "cert_raw" if revocation else "csr"
            dbstore = DBstore(False, self.logger)
            result_dic = dbstore.certificate_lookup(
                search_key,
                csr,
                vlist=[
                    "name",
                    "order__name",
                    "order__account__name",
                    "order__account__eab_kid",
                ],
            )
            if result_dic and "order__account__eab_kid" in result_dic:
                eab_kid = result_dic["order__account__eab_kid"]
            else:
                eab_kid = None
        except Exception as err:
            self.logger.error("Database error while retrieving eab_kid: %s", err)
            eab_kid = None
        self.logger.debug("EABhandler.eab_kid_get() ended with: %s", eab_kid)
        return eab_kid

    def eab_profile_get(self, csr: str, revocation: bool = False) -> Dict[str, Any]:
        """Return the per-kid cahandler profile dict."""
        self.logger.debug("EABhandler._eab_profile_get()")
        profiles_dic = self.key_file_load()
        eab_kid = self.eab_kid_get(csr, revocation=revocation)
        entry = eab_profile_kid_entry_get(profiles_dic, eab_kid)
        profile_dic = entry.get("cahandler", {}) if entry else {}
        if not isinstance(profile_dic, dict):
            profile_dic = {}
        self.logger.debug(
            "EABhandler._eab_profile_get() ended with: %s", bool(profile_dic)
        )
        return profile_dic

    def cahandler_name_get(self, csr: str, revocation: bool = False) -> Optional[str]:
        """Return per-kid cahandler_name registry selector, if configured."""
        self.logger.debug("EABhandler.cahandler_name_get()")
        name = None
        profiles_dic = self.key_file_load()
        eab_kid = self.eab_kid_get(csr, revocation=revocation)
        entry = eab_profile_kid_entry_get(profiles_dic, eab_kid)
        if "cahandler_name" in entry:
            name = entry["cahandler_name"]
        self.logger.debug("EABhandler.cahandler_name_get() ended with: %s", name)
        return name
