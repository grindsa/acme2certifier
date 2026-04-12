# Order Architecture Documentation

## Overview

This document describes the refactored order architecture and provides guidance for understanding and extending the order management system in acme2certifier.

## Architecture Summary

The order subsystem implements a modular, extensible architecture using established design patterns to handle ACME order lifecycle management:

### Design Patterns Implemented

- **Repository Pattern**: Clean separation of data access logic from business logic
- **Business Logic Layer**: Domain-specific order operations and business rules
- **Configuration Pattern**: Centralized configuration management with validation
- **Context Manager Pattern**: Resource management and initialization
- **Exception Hierarchy**: Structured error handling with specific error types
- **Data Transfer Objects**: Structured configuration and data containers

### Component Structure

```
┌─────────────────────────────┐
│         Order Class         │
│   (ACME Protocol Handler)   │
└─────────────┬───────────────┘
              │
    ┌─────────┴─────────┐
    ▼                   ▼
OrderRepository   OrderConfiguration
    │                   │
    ▼                   ▼
  DBstore         Config/Helpers
```

## Core Components

### 1. Order Class (`/acme_srv/order.py`)

The `Order` class is the main entry point for order operations and ACME protocol handling. It provides methods for:

- Order creation, validation, and management
- Authorization and profile handling
- Configuration loading and context management
- Logging and error handling
- Delegation to repository and message subsystems

#### Key Responsibilities

- Implements context manager for resource management
- Delegates data access to the repository layer
- Handles protocol-specific logic and error handling
- Coordinates with authorization and certificate subsystems

### 2. Order Repository (`OrderRepository`)

- Encapsulates all database operations related to orders, authorizations, accounts, and certificates
- Provides methods for CRUD operations and lookups
- Used by the `Order` class for persistent storage
- Raises structured exceptions for error handling

### 3. Configuration and Data Classes (`OrderConfiguration`)

- Centralized configuration management for order handling
- Stores validity periods, feature toggles, limits, and profile settings
- Supports dynamic loading from config files and database
- Used by the `Order` class for runtime configuration

### 4. Error Handling

- Structured exception hierarchy for order operations (`OrderDatabaseError`, `OrderValidationError`)
- Centralized error dictionary and logging
- Graceful handling of database and validation errors

## Extensibility

The order subsystem is designed for easy extension:

- Add new business rules or validation logic in the `Order` class
- Extend repository methods for new database operations
- Add new configuration options in `OrderConfiguration`
- Integrate with external systems via hooks or message handlers

## Sequence Example: Order Creation

```
Client Request
     │
     ▼
Order.create_order() ──▶ Identifier/Profile Validation
     │
     ▼
OrderRepository.add_order()
     │
     ▼
Order._add_authorizations_to_db()
     │
     ▼
OrderRepository.add_authorization()
     │
     ▼
Logging/Audit
     │
     ▼
Response to Client
```

## File Locations

- Order logic: `/acme_srv/order.py`
- Repository: `/acme_srv/order.py` (OrderRepository)
- Configuration: `/acme_srv/order.py` (OrderConfiguration)
- Helpers: `/acme_srv/helper.py`, `/acme_srv/db_handler.py`
- Error handling: `/acme_srv/order.py`, `/acme_srv/error.py`

______________________________________________________________________
