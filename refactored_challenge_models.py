"""
Challenge System Refactoring - Data Models and Exceptions
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from enum import Enum


class ChallengeType(Enum):
    """Enumeration of supported challenge types"""
    HTTP_01 = "http-01"
    DNS_01 = "dns-01"
    TLS_ALPN_01 = "tls-alpn-01"
    EMAIL_REPLY_00 = "email-reply-00"
    TKAUTH_01 = "tkauth-01"
    SECTIGO_EMAIL_01 = "sectigo-email-01"


class ChallengeStatus(Enum):
    """Challenge status enumeration"""
    PENDING = "pending"
    PROCESSING = "processing"
    VALID = "valid"
    INVALID = "invalid"


class IdentifierType(Enum):
    """Identifier type enumeration"""
    DNS = "dns"
    IP = "ip"
    EMAIL = "email"


@dataclass
class ChallengeIdentifier:
    """Challenge identifier information"""
    type: IdentifierType
    value: str


@dataclass
class ChallengeData:
    """Core challenge data structure"""
    name: str
    type: ChallengeType
    status: ChallengeStatus
    token: str
    identifier: ChallengeIdentifier
    authorization_name: str
    account_name: str
    jwk_thumbprint: Optional[str] = None
    key_authorization: Optional[str] = None
    validated_at: Optional[int] = None
    expires: Optional[int] = None
    error_detail: Optional[str] = None


@dataclass
class ValidationContext:
    """Context for challenge validation"""
    challenge_data: ChallengeData
    payload: Dict[str, str]
    dns_server_list: Optional[List[str]] = None
    proxy_server_list: Optional[Dict[str, str]] = None
    timeout: int = 10
    source_address: Optional[str] = None


@dataclass
class ValidationResult:
    """Result of challenge validation"""
    success: bool
    invalid: bool = False
    error_message: Optional[str] = None
    details: Optional[Dict[str, str]] = None


@dataclass
class ChallengeConfiguration:
    """Challenge system configuration"""
    validation_disabled: bool = False
    validation_timeout: int = 10
    dns_validation_pause_timer: float = 0.5
    forward_address_check: bool = False
    reverse_address_check: bool = False
    sectigo_simulation: bool = False
    email_identifier_support: bool = False
    tnauthlist_support: bool = False
    email_address: Optional[str] = None
    dns_server_list: Optional[List[str]] = None
    proxy_server_list: Optional[Dict[str, str]] = None


# Custom Exceptions

class ChallengeError(Exception):
    """Base exception for challenge-related errors"""
    pass


class ChallengeNotFoundError(ChallengeError):
    """Raised when a challenge cannot be found"""
    pass


class ChallengeValidationError(ChallengeError):
    """Raised when challenge validation fails"""
    pass


class ChallengeConfigurationError(ChallengeError):
    """Raised when challenge configuration is invalid"""
    pass


class ChallengeNetworkError(ChallengeError):
    """Raised when network-related validation fails"""
    pass


class ChallengeDatabaseError(ChallengeError):
    """Raised when database operations fail"""
    pass


class UnsupportedChallengeTypeError(ChallengeError):
    """Raised when an unsupported challenge type is encountered"""
    pass