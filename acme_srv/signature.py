# -*- coding: utf-8 -*-
"""Signature class"""
from __future__ import print_function
from typing import Tuple, Dict, Optional
from acme_srv.helper import signature_check, load_config, error_dic_get
from acme_srv.db_handler import DBstore


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
                f"Database error: failed to load {'CLI ' if cli else ''}JWK for account id {kid}: {err_}"
            )
            return None

    def cli_check(self, aname: str, content: str) -> Tuple[bool, str, None]:
        """Check signature against CLI key for account."""
        self.logger.debug(f"Signature.cli_check({aname})")
        if not content:
            return (False, self.err_msg_dic["malformed"], None)
        if not aname:
            return (False, self.err_msg_dic["accountdoesnotexist"], None)
        pub_key = self._jwk_loader(aname, cli=True)
        if not pub_key:
            return (False, self.err_msg_dic["accountdoesnotexist"], None)
        result, error = signature_check(self.logger, content, pub_key)
        self.logger.debug(f"Signature.cli_check() ended with: {result}:{error}")
        return (result, error, None)

    def check(
        self,
        aname: str,
        content: str,
        use_emb_key: bool = False,
        protected: Dict[str, str] = None,
    ) -> Tuple[bool, str, None]:
        """Check signature against account key or embedded JWK."""
        self.logger.debug(f"Signature.check({aname})")
        if not content:
            return (False, self.err_msg_dic["malformed"], None)
        error = None
        if aname:
            pub_key = self._jwk_loader(aname)
            if not pub_key:
                error = self.err_msg_dic["accountdoesnotexist"]
                return (False, error, None)
            result, error = signature_check(self.logger, content, pub_key)
            self.logger.debug(f"Signature.check() ended with: {result}:{error}")
            return (result, error, None)
        elif use_emb_key:
            self.logger.debug(
                "Signature.check() check signature against key included in jwk"
            )
            if protected and "jwk" in protected:
                pub_key = protected["jwk"]
                result, error = signature_check(self.logger, content, pub_key)
                self.logger.debug(f"Signature.check() ended with: {result}:{error}")
                return (result, error, None)
            else:
                error = self.err_msg_dic["accountdoesnotexist"]
                return (False, error, None)
        else:
            error = self.err_msg_dic["accountdoesnotexist"]
            return (False, error, None)

    def eab_check(self, content: str, mac_key: str) -> Tuple[bool, str]:
        """Check signature for External Account Binding (EAB)."""
        self.logger.debug("Signature.eab_check()")
        if not (content and mac_key):
            return (False, self.err_msg_dic["malformed"])
        result, error = signature_check(self.logger, content, mac_key, json_=True)
        self.logger.debug(f"Signature.eab_check() ended with: {result}:{error}")
        return (result, error)
