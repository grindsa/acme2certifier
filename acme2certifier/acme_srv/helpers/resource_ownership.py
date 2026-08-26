# -*- coding: utf-8 -*-
"""Account-to-resource ownership checks for authenticated ACME requests."""

from __future__ import annotations

import logging
from typing import Optional, Tuple

UNAUTHORIZED_TYPE = "urn:ietf:params:acme:error:unauthorized"
SERVER_INTERNAL_TYPE = "urn:ietf:params:acme:error:serverInternal"
OWNERSHIP_DENIED_DETAIL = "Unauthorized"


class ResourceOwnershipLookupError(Exception):
    """Raised when the owning account cannot be loaded from the database."""


def resource_owner_matches(
    requester_account: Optional[str], resource_owner: Optional[str]
) -> bool:
    """Return True only when both accounts are non-empty and equal."""
    if not requester_account or not resource_owner:
        return False
    return requester_account == resource_owner


def ownership_unauthorized() -> Tuple[int, str, str]:
    """Standard ACME response tuple for an ownership violation."""
    return (403, UNAUTHORIZED_TYPE, OWNERSHIP_DENIED_DETAIL)


def ownership_lookup_failed() -> Tuple[int, str, str]:
    """Standard ACME response tuple for an owner lookup database failure."""
    return (500, SERVER_INTERNAL_TYPE, "Database error")


def log_ownership_denial(
    logger: logging.Logger,
    requester_account: Optional[str],
    resource_type: str,
    resource_name: str,
) -> None:
    """Log a cross-account or missing-owner access attempt."""
    logger.warning(
        "resource access denied: unauthorized account=%s resource=%s name=%s",
        requester_account,
        resource_type,
        resource_name,
    )
