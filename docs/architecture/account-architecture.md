# Account Architecture Documentation

## Overview

This document describes the refactored account architecture and provides guidance for understanding and extending the account management system in acme2certifier.

## Architecture Summary

The account subsystem implements a modular, extensible architecture using established design patterns to handle ACME account lifecycle management:

### Design Patterns Implemented

- **Repository Pattern**: Clean separation of data access logic from business logic
- **Business Logic Layer**: Domain-specific account operations and business rules
- **Configuration Pattern**: Centralized configuration management with validation
- **Context Manager Pattern**: Resource management and initialization
- **Exception Hierarchy**: Structured error handling with specific error types
- **Data Transfer Objects**: Structured configuration and data containers

### Component Structure

```text
┌─────────────────────────────────────────────────────────────┐
│                    Account Class                            │
│               (ACME Protocol Handler)                       │
└─────────────────────────────┬───────────────────────────────┘
                              │
        ┌───────────────┬───────────────┬───────────────┐
        │               │               │               │
        ▼               ▼               ▼               ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│AccountRepo  │ │AccountLogic │ │AccountConfig│ │AccountDTO   │
│(DB access)  │ │(Business    │ │(Config      │ │(Data        │
│             │ │ Logic)      │ │ Object)     │ │ Transfer)   │
└─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘
        │               │               │               │
        ▼               ▼               ▼               ▼
    DBstore        Validation      Helpers        Error/Logger
```

## Core Components

### 1. Account Class (`/acme_srv/account.py`)

The `Account` class is the main entry point for account operations and ACME protocol handling. It provides methods for:

- Account creation and registration
- Account status management
- Key rollover and update
- External Account Binding (EAB) support
- Error handling and logging

### 2. AccountRepository

Handles all database-related operations for accounts, abstracting the underlying database handler. Key responsibilities:

- Fetching and storing account data
- Managing account status and keys
- Logging and error handling for database access

### 3. AccountBusinessLogic

Implements domain-specific business rules for account management, including:

- Validation of account requests
- Key management and rollover logic
- EAB validation and processing

### 4. AccountConfig

Centralizes configuration management for account operations, supporting:

- Feature toggles (e.g., EAB, key rollover)
- Validation rules
- Integration with external systems

## Configuration Loading

The account subsystem loads its configuration from external sources using helper functions. It parses:

- Feature flags
- Validation rules
- EAB parameters
- Logging and error handling settings

## Error Handling

A structured exception hierarchy is used to provide robust error handling, including:

- Specific error types for account operations
- Logging and reporting mechanisms
- Integration with ACME protocol error responses

---
