# -*- coding: utf-8 -*-
"""Signature class"""

from __future__ import print_function
from typing import Tuple, Dict, Optional
from acme2certifier.acme_srv.helper import (
    error_dic_get,
    load_config,
    signature_check,
    unsupported_jwk_detail,
)
from acme2certifier.acme_srv.db_handler import DBstore
from acme2certifier.acme_srv.helpers.global_variables import DB_ERROR_MSG
from acme2certifier.acme_srv.helpers.otel import (
    ATTR_AUTH_KIND,
    COUNTER_AUTH_FAILURE,
    counter_add,
)

SIG_CHECK_ACCOUNT_MISSING_LOG = (
    "Signature check failed: account does not exist account=%s"
)
UNSUPPORTED_AKP_DETAIL_PREFIX = 'JWK key type "AKP"'


class Signature:
    """Handles signature verification and key loading for ACME accounts."""

    def __init__(
        self, debug: bool = False, srv_name: str = None, logger: object = None
    ):
        self.debug = debug
        self.logger = logger
        self.dbstore = DBstore(self.debug, self.logger)
        self.err_msg_dic = error_dic_get(self.logger)
        self.server_name = srv_name
        cfg = load_config()
        self.revocation_path = self._get_revocation_path(cfg)

    def _get_revocation_path(self, cfg) -> str:
        if "Directory" in cfg and "url_prefix" in cfg["Directory"]:
            return cfg["Directory"]["url_prefix"] + "/acme/revokecert"
        return "/acme/revokecert"

    def _jwk_loader(self, kid, cli: bool = False) -> Optional[Dict[str, str]]:
        """Load JWK for a specific account id, optionally using CLI method."""
        method = self.dbstore.cli_jwk_load if cli else self.dbstore.jwk_load
        self.logger.debug(f"Signature._jwk_loader({kid}, cli={cli})")
        try:
            return method(kid)
        except Exception as err_:
            self.logger.critical(
                f"{DB_ERROR_MSG}: failed to load {'CLI ' if cli else ''}JWK for account id {kid}: {err_}"
            )
            return None

    def _jws_verify_result(
        self, content: str, pub_key: Dict[str, str]
    ) -> Tuple[bool, str, Optional[str]]:
        """Verify JWS; map unsupported AKP JWKs to badPublicKey + detail."""
        detail = unsupported_jwk_detail(self.logger, pub_key)
        if detail:
            counter_add(
                COUNTER_AUTH_FAILURE,
                attributes={ATTR_AUTH_KIND: "jws"},
            )
            return (False, self.err_msg_dic["badpubkey"], detail)

        result, error = signature_check(self.logger, content, pub_key)
        if not result:
            counter_add(
                COUNTER_AUTH_FAILURE,
                attributes={ATTR_AUTH_KIND: "jws"},
            )
            # Defense in depth if signature_check returned the AKP detail string.
            if error and error.startswith(UNSUPPORTED_AKP_DETAIL_PREFIX):
                return (False, self.err_msg_dic["badpubkey"], error)
            return (False, error, None)
        return (result, error, None)

    def cli_check(
        self, aname: str, content: str
    ) -> Tuple[bool, str, Optional[str]]:
        """Check signature against CLI key for account."""
        self.logger.debug(f"Signature.cli_check({aname})")
        if not content:
            self.logger.warning(
                "Signature check failed: empty content account=%s", aname
            )
            return (False, self.err_msg_dic["malformed"], None)
        if not aname:
            self.logger.warning(SIG_CHECK_ACCOUNT_MISSING_LOG, aname)
            return (False, self.err_msg_dic["accountdoesnotexist"], None)
        pub_key = self._jwk_loader(aname, cli=True)
        if not pub_key:
            self.logger.warning(SIG_CHECK_ACCOUNT_MISSING_LOG, aname)
            return (False, self.err_msg_dic["accountdoesnotexist"], None)
        result, error, detail = self._jws_verify_result(content, pub_key)
        self.logger.debug(f"Signature.cli_check() ended with: {result}:{error}")
        return (result, error, detail)

    def check(
        self,
        aname: str,
        content: str,
        use_emb_key: bool = False,
        protected: Dict[str, str] = None,
    ) -> Tuple[bool, str, Optional[str]]:
        """Check signature against account key or embedded JWK."""
        self.logger.debug(f"Signature.check({aname})")
        if not content:
            self.logger.warning(
                "Signature check failed: empty content account=%s", aname
            )
            return (False, self.err_msg_dic["malformed"], None)
        if aname:
            pub_key = self._jwk_loader(aname)
            if not pub_key:
                self.logger.warning(SIG_CHECK_ACCOUNT_MISSING_LOG, aname)
                return (False, self.err_msg_dic["accountdoesnotexist"], None)
            result, error, detail = self._jws_verify_result(content, pub_key)
            self.logger.debug(f"Signature.check() ended with: {result}:{error}")
            return (result, error, detail)
        elif use_emb_key:
            self.logger.debug(
                "Signature.check() check signature against key included in jwk"
            )
            if protected and "jwk" in protected:
                pub_key = protected["jwk"]
                result, error, detail = self._jws_verify_result(content, pub_key)
                self.logger.debug(f"Signature.check() ended with: {result}:{error}")
                return (result, error, detail)
            else:
                self.logger.warning("Signature check failed: embedded JWK missing")
                counter_add(
                    COUNTER_AUTH_FAILURE,
                    attributes={ATTR_AUTH_KIND: "jws"},
                )
                return (False, self.err_msg_dic["accountdoesnotexist"], None)
        else:
            self.logger.warning(
                "Signature check failed: missing kid and no embedded JWK"
            )
            counter_add(
                COUNTER_AUTH_FAILURE,
                attributes={ATTR_AUTH_KIND: "jws"},
            )
            return (False, self.err_msg_dic["accountdoesnotexist"], None)

    def eab_check(self, content: str, mac_key: str) -> Tuple[bool, str]:
        """Check signature for External Account Binding (EAB)."""
        self.logger.debug("Signature.eab_check()")
        if not (content and mac_key):
            counter_add(
                COUNTER_AUTH_FAILURE,
                attributes={ATTR_AUTH_KIND: "eab"},
            )
            return (False, self.err_msg_dic["malformed"])
        result, error = signature_check(self.logger, content, mac_key, json_=True)
        self.logger.debug(f"Signature.eab_check() ended with: {result}:{error}")
        if not result:
            counter_add(
                COUNTER_AUTH_FAILURE,
                attributes={ATTR_AUTH_KIND: "eab"},
            )
        return (result, error)
