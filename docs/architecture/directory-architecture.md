# Directory Architecture

## Overview

The `Directory` concept in acme2certifier provides a modular, extensible, and testable approach to handling ACME Directory logic, configuration, and response building. It is designed to separate concerns, facilitate maintainability, and support robust integration with external systems such as databases and CA handlers.

## Components

### 1. DirectoryConfig

A dataclass encapsulating all configuration parameters for the Directory, including:

- Version and product information
- Terms of Service URL
- URL prefix and home URL
- CA identities and profiles
- External Account Binding (EAB) support
- Boolean flags for feature toggles

### 2. DirectoryRepository

Handles all database-related operations for the Directory, abstracting the underlying database handler. Key responsibilities:

- Fetching the current database version
- Logging and error handling for database access

### 3. Directory

The main handler class orchestrating configuration loading, repository access, CA handler integration, and response construction. Key features:

- Context manager support for safe configuration loading
- Modular configuration parsing (sections, booleans, EAB, profiles)
- CA handler loading and validation
- Meta information and directory response building
- Public API for ACME directory endpoint responses

## Configuration Loading

The Directory loads its configuration from external sources using helper functions. It parses:

- The `[Directory]` section for basic values
- Boolean flags for feature toggles
- EAB and profile settings
- CA handler module for certificate operations

## Response Construction

The Directory builds responses for the ACME directory endpoint, including:

- Standard ACME endpoints (newAuthz, newNonce, newAccount, etc.)
- Meta information (product, version, ToS, CA identities, profiles, EAB)
- Database schema validation status
- Randomized entries for security best practices

## Extensibility & Testability

- All dependencies (logger, dbstore, CA handler) are injectable for easy testing and extension.
- Comprehensive unittests cover all major logic branches, including configuration parsing, error handling, and response generation.
- Type annotations and docstrings improve code clarity and static analysis.

## Error Handling

- Centralized logging for configuration and database errors
- Graceful fallback for missing or invalid configuration values
- Clear error responses for CA handler issues

## Security Considerations

- Randomized directory entries to mitigate enumeration attacks
- Configurable external account binding and CA identity support
- Logging avoids exposing sensitive data

## References

- See other architecture docs in `docs/architecture/` for integration patterns and design principles.
- ACME RFC 8555 for protocol details.
