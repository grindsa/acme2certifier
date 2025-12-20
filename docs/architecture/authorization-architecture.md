# Authorization Architecture Documentation

## Overview

This document describes the refactored authorization architecture and provides guidance for understanding and extending the authorization system in acme2certifier.

## Architecture Summary

The refactored authorization system implements a clean, modular architecture using established design patterns to handle ACME authorization lifecycle management:

### Design Patterns Implemented

- **Repository Pattern**: Clean separation of data access logic from business logic
- **Business Logic Layer**: Domain-specific authorization operations and business rules
- **Configuration Pattern**: Centralized configuration management with validation
- **Manager Pattern**: Specialized managers for challenge set operations
- **Data Transfer Objects**: Structured data containers with validation
- **Context Manager Pattern**: Resource management and initialization
- **Exception Hierarchy**: Structured error handling with specific error types

### Component Structure

```text
┌─────────────────────────────────────────────────────────────┐
│                  Authorization Class                        │
│               (ACME Protocol Handler)                       │
└──────────────────────┬──────────────────────────────────────┘
                       │
    ┌──────────────────┼──────────────────┐
    │                  │                  │
    ▼                  ▼                  ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│Authorization    │ │Authorization    │ │ChallengeSet     │
│Repository       │ │BusinessLogic    │ │Manager          │
│                 │ │                 │ │                 │
└─────────────────┘ └─────────────────┘ └─────────────────┘
    │                  │                  │
    ▼                  ▼                  ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  DBstore        │ │AuthorizationData│ │Challenge        │
│  Database Ops   │ │AuthorizationConf│ │Integration      │
└─────────────────┘ └─────────────────┘ └─────────────────┘
    │
    ▼
┌─────────────────┐
│  SQLite/MySQL   │
│  Database       │
└─────────────────┘
```

## Core Components

### 1. Data Models (`AuthorizationConfig` & `AuthorizationData`)

Data structures that define authorization configuration and runtime data:

#### `AuthorizationConfig`

```python
@dataclass
class AuthorizationConfig:
    """Configuration for Authorization operations"""

    validity: int = 86400  # Default 24 hours
    expiry_check_disable: bool = False
    authz_path: str = "/acme/authz/"
```

**Responsibilities:**

- Store authorization validity period configuration
- Control expiry checking behavior
- Define URL path structure

#### `AuthorizationData`

```python
@dataclass
class AuthorizationData:
    """Authorization data structure"""

    name: str
    status: str
    expires: int
    token: str
    identifier: Optional[Dict[str, str]] = None
    challenges: Optional[List[Dict[str, str]]] = None
    wildcard: bool = False
```

**Responsibilities:**

- Structured representation of authorization data
- ACME-compliant serialization via `to_dict()` method
- Type safety and validation

### 2. Repository Layer (`AuthorizationRepository`)

Handles all database operations with clean abstraction:

```python
class AuthorizationRepository:
    """Repository class for authorization database operations"""
```

**Key Methods:**

- `find_authorization_by_name()`: Retrieve authorization by name with optional field filtering
- `update_authorization_expiry()`: Update authorization expiry and token
- `search_expired_authorizations()`: Find authorizations eligible for expiry
- `mark_authorization_as_expired()`: Update authorization status to expired

**Responsibilities:**

- Abstract database operations from business logic
- Handle database errors with proper exception wrapping
- Provide clean interface for data access
- Support flexible field selection for performance optimization

**Error Handling:**

- Catches all database exceptions
- Wraps in custom `AuthorizationError` with context
- Maintains error logs for debugging

### 3. Business Logic Layer (`AuthorizationBusinessLogic`)

Implements authorization domain logic and business rules:

```python
class AuthorizationBusinessLogic:
    """Business logic for authorization operations"""
```

**Key Methods:**

- `extract_authorization_name_from_url()`: Parse authorization name from ACME URLs
- `generate_authorization_token_and_expiry()`: Create new tokens with proper expiry
- `enrich_authorization_with_identifier_info()`: Process identifier data for ACME response
- `extract_identifier_info_for_challenge()`: Extract identifier for challenge operations
- `is_authorization_eligible_for_expiry()`: Business rules for expiry eligibility

**Responsibilities:**

- Implement authorization business rules
- Handle identifier processing and validation
- Token generation and expiry calculation
- Wildcard domain handling
- TNAuthList detection and processing

**Special Features:**

- **Wildcard Support**: Automatic detection and processing of wildcard domains (`*.example.com`)
- **TNAuthList Support**: Special handling for telecommunications authentication lists
- **URL Processing**: Clean extraction of authorization names from ACME protocol URLs
- **Expiry Logic**: Sophisticated rules for determining expiry eligibility

### 4. Challenge Set Manager (`ChallengeSetManager`)

Manages integration with the challenge subsystem:

```python
class ChallengeSetManager:
    """Manager for challenge set operations"""
```

**Responsibilities:**

- Interface with the Challenge system
- Generate appropriate challenge sets for authorizations
- Handle TNAuth and standard challenge requirements
- Pass through identifier information for challenge generation

**Integration Points:**

- Creates Challenge instances with proper configuration
- Delegates to `challenge.challengeset_get()` for actual challenge generation
- Manages challenge expiry alignment with authorization expiry

### 5. Main Authorization Class (`Authorization`)

The primary interface for authorization operations:

```python
class Authorization(object):
    """Refactored Authorization class with clear separation of concerns"""
```

**Public API Methods:**

#### ACME Protocol Methods

- `handle_get_request(url: str)`: Process ACME GET requests for authorization details
- `handle_post_request(content: str)`: Process ACME POST requests for authorization updates
- `get_authorization_details(url: str)`: Retrieve detailed authorization information
- `expire_invalid_authorizations(timestamp: int)`: Expire authorizations past their validity

#### Backward Compatibility Methods

- `new_get(url: str)`: Legacy GET request handler
- `new_post(content: str)`: Legacy POST request handler
- `invalidate(timestamp: int)`: Legacy expiry method
- `_authz_info(url: str)`: Legacy authorization info method

**Context Manager Support:**

```python
with Authorization(debug=True, srv_name="example.com", logger=logger) as authz:
    result = authz.handle_get_request("/acme/authz/abc123")
```

**Initialization Strategy:**

- Eager initialization of all components in `__init__()`
- Configuration loading and component re-initialization in `__enter__()`
- No cleanup required in `__exit__()`

### 6. Exception Hierarchy

Structured error handling with specific exception types:

```python
# Base exception
class AuthorizationError(Exception):
    """Base exception for authorization operations"""


# Specific exceptions
class AuthorizationNotFoundError(AuthorizationError):
    """Raised when authorization is not found"""


class AuthorizationExpiredError(AuthorizationError):
    """Raised when authorization has expired"""


class ConfigurationError(AuthorizationError):
    """Raised when configuration is invalid"""
```

**Error Handling Strategy:**

- Database errors wrapped in `AuthorizationError` with context
- Configuration validation raises `ConfigurationError`
- Clear error messages with actionable details
- Comprehensive error logging

## Design Principles

### 1. Separation of Concerns

Each component has a single, well-defined responsibility:

- **Repository**: Database operations only
- **BusinessLogic**: Domain rules and processing
- **ChallengeSetManager**: Challenge system integration
- **Authorization**: ACME protocol handling and coordination

### 2. Clean Architecture

```text
┌─────────────────┐
│   Controllers   │ ← Authorization (ACME Protocol)
│   (Interface)   │
└─────────────────┘
         │
┌─────────────────┐
│ Business Logic  │ ← AuthorizationBusinessLogic
│   (Use Cases)   │
└─────────────────┘
         │
┌─────────────────┐
│   Repository    │ ← AuthorizationRepository
│  (Data Access)  │
└─────────────────┘
         │
┌─────────────────┐
│   Database      │ ← DBstore
│ (External API)  │
└─────────────────┘
```

### 3. Dependency Injection

Components are composed with clear dependencies:

```python
# Clean dependency chain
config = AuthorizationConfig()
repository = AuthorizationRepository(dbstore, logger)
business_logic = AuthorizationBusinessLogic(config, repository, logger)
challenge_manager = ChallengeSetManager(debug, server_name, logger)
```

### 4. Immutable Configuration

Configuration is loaded once and treated as immutable:

- Configuration loading separated from business logic
- Validation at load time with clear error messages
- Type safety with dataclass structure

### 5. Comprehensive Error Handling

Structured error handling at every layer:

- Custom exception hierarchy with specific error types
- Context preservation through exception chaining
- Detailed error logging for debugging
- ACME-compliant error responses

## Key Workflows

### 1. Authorization Request Processing (GET)

```text
1. Authorization.handle_get_request(url)
2. BusinessLogic.extract_authorization_name_from_url(url)
3. Repository.find_authorization_by_name(name)
4. BusinessLogic.generate_authorization_token_and_expiry()
5. Repository.update_authorization_expiry(name, token, expires)
6. Repository.find_authorization_by_name(name, detailed_fields)
7. BusinessLogic.enrich_authorization_with_identifier_info(auth_details)
8. ChallengeSetManager.get_challenge_set_for_authorization(...)
9. Return ACME-compliant authorization object
```

### 2. Authorization Update Processing (POST)

```text
1. Authorization.handle_post_request(content)
2. [Optional] Authorization.expire_invalid_authorizations()
3. Message.check(content) [Message validation]
4. BusinessLogic.extract_authorization_name_from_url(protected.url)
5. Authorization.get_authorization_details(url)
6. Message.prepare_response(data, status)
7. Return ACME-compliant response
```

### 3. Authorization Expiry Processing

```text
1. Authorization.expire_invalid_authorizations(timestamp)
2. Repository.search_expired_authorizations(timestamp, fields)
3. For each expired authorization:
   a. BusinessLogic.is_authorization_eligible_for_expiry(auth)
   b. Repository.mark_authorization_as_expired(auth.name)
4. Return list of expired authorizations
```
