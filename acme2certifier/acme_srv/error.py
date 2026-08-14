#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Error class — ACME problem detail enrichment only.

Operator-visible ACME problem logging lives in Message.prepare_response.
"""

from __future__ import print_function
from typing import Any, Optional


class Error(object):
    """error messages"""

    def __init__(self, debug: Any = None, logger: Any = None) -> None:
        self.debug = debug
        self.logger = logger

    def _acme_errormessage(self, message: Optional[str]) -> Optional[str]:
        """dictionary containing the implemented acme error messages"""
        error_dic = {
            "urn:ietf:params:acme:error:accountDoesNotExist": None,
            "urn:ietf:params:acme:error:badCSR": None,
            "urn:ietf:params:acme:error:badNonce": "JWS has invalid anti-replay nonce",
            "urn:ietf:params:acme:error:invalidContact": "The provided contact URI was invalid",
            "urn:ietf:params:acme:error:malformed": None,
            "urn:ietf:params:acme:error:serverInternal": None,
            "urn:ietf:params:acme:error:unauthorized": None,
            "urn:ietf:params:acme:error:userActionRequired": None,
            "urn:ietf:params:acme:error:alreadyRevoked": None,
            "notImplementedYet": "we are not that far. Stay tuned",
        }
        if message and message in error_dic:
            return error_dic[message]
        return None

    def enrich_error(
        self, message: Optional[str], detail: Optional[str] = None
    ) -> Optional[str]:
        """Prefix detail with a static ACME error description when available."""
        error_message = self._acme_errormessage(message)

        if message and error_message:
            detail = f"{error_message}: {detail}"
        elif error_message:
            detail = f"{error_message}{detail}"

        return detail
