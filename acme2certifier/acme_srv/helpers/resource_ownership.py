# -*- coding: utf-8 -*-
"""Account-to-resource ownership checks for authenticated ACME requests."""

import logging
from typing import Callable, Optional, Tuple

UNAUTHORIZED_TYPE = "urn:ietf:params:acme:error:unauthorized"
SERVER_INTERNAL_TYPE = "urn:ietf:params:acme:error:serverInternal"
OWNERSHIP_DENIED_DETAIL = "Unauthorized"

OwnershipResult = Tuple[int, Optional[str], Optional[str]]
OwnerLookup = Callable[[], Optional[str]]


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


def check_resource_ownership(
    logger: logging.Logger,
    requester_account: Optional[str],
    resource_type: str,
    resource_name: str,
    owner: Optional[str],
) -> OwnershipResult:
    """Compare requester and owner; deny with a 403 when they do not match."""
    if not resource_owner_matches(requester_account, owner):
        log_ownership_denial(logger, requester_account, resource_type, resource_name)
        return ownership_unauthorized()
    return (200, None, None)


def resolve_resource_ownership(
    logger: logging.Logger,
    requester_account: Optional[str],
    resource_type: str,
    resource_name: str,
    lookup: OwnerLookup,
) -> OwnershipResult:
    """Run *lookup* then check ownership; map lookup failures to HTTP 500."""
    try:
        owner = lookup()
    except ResourceOwnershipLookupError:
        return ownership_lookup_failed()
    return check_resource_ownership(
        logger, requester_account, resource_type, resource_name, owner
    )
