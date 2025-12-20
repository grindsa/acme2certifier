# Renewalinfo Architecture Documentation

## Overview

This document describes the architecture of the refactored Renewalinfo subsystem, which manages ACME renewal information. The design emphasizes separation of concerns, robust error handling, and testability.

## Architecture Summary

The Renewalinfo subsystem implements a modular, maintainable architecture using established design patterns:

### Design Patterns Implemented

- **Repository Pattern**: Encapsulates all data access logic for certificates and housekeeping parameters.
- **Configuration Object Pattern**: Centralizes configuration management using a dataclass.
- **Context Manager Pattern**: Ensures proper initialization and resource management.
- **Separation of Concerns**: Distinct classes for business logic, configuration, and data access.
- **Mockable Interfaces**: All external dependencies are easily mockable for testing.

### Component Structure

```text
┌─────────────────────────────────────────────────────────────┐
│                    Renewalinfo Class                        │
│              (ACME Renewal Info Handler)                    │
└──────────────────────┬──────────────────────────────────────┘
                       │
    ┌──────────────────┼──────────────────┐
    │                  │                  │
    ▼                  ▼                  ▼
┌──────────────┐ ┌──────────────┐ ┌────────────────────┐
│ RenewalinfoConfig │ │ Repository     │ │   Message/Logger    │
│                    │ │ (DB access)    │ │ (Error, Logging)    │
└──────────────┘ └──────────────┘ └────────────────────┘
                       │
                       ▼
                ┌──────────────┐
                │   Database   │
                └──────────────┘
```

## Core Components

### 1. RenewalinfoConfig (`acme_srv/renewalinfo.py`)

- **Purpose**: Holds all configuration parameters for renewal logic (e.g., renewal_force, threshold, retry timeout).
- **Implementation**: Python dataclass for type safety and clarity.

### 2. RenewalinfoRepository (`acme_srv/renewalinfo.py`)

- **Purpose**: Encapsulates all database access for certificates and housekeeping parameters.
- **Responsibilities**:
  - Certificate lookup by certid or serial/AKI
  - Adding certificates
  - Housekeeping parameter management
- **Benefits**: Clean separation from business logic, easy to mock for testing.

### 3. Renewalinfo (Main Handler, `acme_srv/renewalinfo.py`)

- **Purpose**: Implements all business logic for ACME renewal info endpoints.
- **Responsibilities**:
  - Loads and manages configuration
  - Handles context management (with statement)
  - Orchestrates certificate lookups and renewal window calculation
  - Provides public `get()` and `update()` methods for API compatibility
  - Centralizes error handling and logging
- **Design**: Delegates all data access to the repository and all configuration to the config object.

### 4. Message and Logger

- **Purpose**: Handles error messages, logging, and protocol-specific message parsing.
- **Integration**: Passed as dependencies to Renewalinfo for full testability.

## Key Flows

### Certificate Lookup and Renewal Info Generation

1. **Request Handling**: Public `get()` method receives a URL, parses the renewal info string.
2. **Housekeeping**: Ensures certificate table is up-to-date (triggers update if needed).
3. **Certificate Lookup**: Uses repository to find certificate by certid or serial/AKI.
4. **Renewal Window Calculation**: Computes suggested renewal window based on config and certificate data.
5. **Response Construction**: Returns structured response with renewal info or error details.

### Configuration Loading

- Loads from config file using a harmonized approach.
- All parsing errors are logged and fallback values are used.

### Error Handling

- All database and configuration errors are logged with context.
- Fallbacks and safe defaults are used to ensure robust operation.

## Extensibility

- **New Data Sources**: Add methods to the repository.
- **New Business Rules**: Extend the main handler logic.
- **Testing**: All dependencies are mockable; comprehensive unittests are provided.

## File Structure

```text
acme_srv/
├── renewalinfo.py         # Main handler, config, repository
├── db_handler.py          # Database abstraction
├── message.py             # Protocol message handling
```
