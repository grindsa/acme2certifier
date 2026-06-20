# -*- coding: utf-8 -*-
"""Nonce class"""

from __future__ import print_function
import uuid
from typing import Tuple, Dict
from dataclasses import dataclass
from acme_srv.db_handler import DBstore
from acme_srv.helper import uts_now, load_config


# Custom Exceptions
class NonceError(Exception):
    """Base exception for nonce operations"""

    # pylint: disable=unnecessary-pass
    pass


class ConfigurationError(NonceError):
    """Raised when configuration is invalid"""

    # pylint: disable=unnecessary-pass
    pass


class NonceRepository:
    """Repository class for Nonce operations."""

    def __init__(self, dbstore) -> None:
        self.dbstore = dbstore

    def check_nonce(self, nonce) -> bool:
        return self.dbstore.nonce_check(nonce)

    def delete_nonce(self, nonce) -> None:
        return self.dbstore.nonce_delete(nonce)

    def add_nonce(self, nonce) -> int:
        return self.dbstore.nonce_add(nonce)

    def delete_nonces(self, nonce_list) -> int:
        return self.dbstore.nonce_delete_bulk(nonce_list)

    def search_expired_nonces(self, timestamp: int) -> Tuple[list, list]:
        return self.dbstore.nonce_search_by_timestamp(timestamp)


@dataclass
class NonceConfiguration:
    """Configuration for Nonce operations"""

    validity: int = 7200


class Nonce(object):
    """Nonce handler"""

    def __init__(self, debug: bool = False, logger: object = None, repo: object = None):
        self.debug = debug
        self.logger = logger
        self.config = NonceConfiguration()
        self.repo = repo or NonceRepository(DBstore(self.debug, self.logger))

    def __enter__(self):
        """Makes ACMEHandler a Context Manager"""
        self._load_configuration()
        return self

    def __exit__(self, *args):
        """Close the connection at the end of the context"""

    def _load_configuration(self):
        """load configuratoion"""

        config_dic = load_config()

        if config_dic:

            try:
                self.config.validity = int(
                    config_dic.get("Nonce", "validity", fallback=self.config.validity)
                )
            except ValueError as err:
                raise ConfigurationError(
                    f"Invalid validity parameter: {config_dic.get('Nonce', 'validity')}"
                ) from err

    def _validate_and_consume_nonce(self, nonce: str) -> Tuple[int, str, str]:
        """Check if nonce exists and delete it (consume)."""
        self.logger.debug("Nonce._validate_and_consume_nonce(%s)", nonce)
        try:
            nonce_chk_result = self.repo.check_nonce(nonce)
        except Exception as err_:
            self.logger.critical("Database error: failed to check nonce: %s", err_)
            nonce_chk_result = False

        if nonce_chk_result:
            try:
                self.repo.delete_nonce(nonce)
            except Exception as err_:
                self.logger.critical("Database error: failed to delete nonce: %s", err_)
            code = 200
            message = None
            detail = None
        else:
            code = 400
            message = "urn:ietf:params:acme:error:badNonce"
            detail = nonce
        self.logger.debug("Nonce._validate_and_consume_nonce() ended with:%s", code)
        return (code, message, detail)

    def _generate_nonce_value(self) -> str:
        """Generate a new nonce value."""
        self.logger.debug("Nonce._generate_nonce_value()")
        return uuid.uuid4().hex

    def check(self, protected_decoded: Dict[str, str]) -> Tuple[int, str, str]:
        """Check nonce (public method, backward compatible)."""
        self.logger.debug("Nonce.check_nonce()")
        if "nonce" in protected_decoded:
            code, message, detail = self._validate_and_consume_nonce(
                protected_decoded["nonce"]
            )
        else:
            code = 400
            message = "urn:ietf:params:acme:error:badNonce"
            detail = "NONE"
        self.logger.debug("Nonce.check_nonce() ended with:%s", code)
        return (code, message, detail)

    def generate_and_add(self) -> str:
        """Generate new nonce and store it (public method, backward compatible)."""
        self.logger.debug("Nonce.generate_and_add()")
        nonce = self._generate_nonce_value()
        self.logger.debug("got nonce: %s", nonce)
        try:
            self.repo.add_nonce(nonce)
        except Exception as err_:
            self.logger.critical("Database error: failed to add new nonce: %s", err_)
        self.logger.debug("Nonce.generate_and_add() ended with:%s", nonce)
        return nonce

    def expire_nonces(self, timestamp: int = uts_now()) -> Tuple[list, list]:
        """Expire nonces based on expiry date."""
        self.logger.debug("Nonce.expire_nonces()")
        nonce_list = []
        total_deleted = 0

        if self.config.validity <= 0:
            self.logger.warning(
                "Nonce.expire_nonces() skipped: validity is set to %s, which means no expiration.",
                self.config.validity,
            )
            return ([], [])  # Return empty lists as no nonces are expired

        try:
            nonce_list = self.repo.search_expired_nonces(
                timestamp - self.config.validity
            )
            if nonce_list:
                total_deleted = self.repo.delete_nonces(nonce_list)
        except Exception as err_:
            self.logger.critical(
                "Database error: failed to search expired nonces: %s", err_
            )
        self.logger.debug(
            "Nonce.expire_nonces() ended with: %s entries, %s deleted",
            len(nonce_list),
            total_deleted,
        )
        return (
            [],
            nonce_list,
        )  # Return empty list for field_list as it's not used in this context
