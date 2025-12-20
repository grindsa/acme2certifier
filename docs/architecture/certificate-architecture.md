# Certificate Architecture Documentation

## Overview

This document describes the refactored certificate architecture and provides guidance for understanding and extending the certificate management system in acme2certifier.

## Architecture Summary

The certificate subsystem implements a modular, extensible architecture using established design patterns to handle ACME certificate lifecycle management:

### Design Patterns Implemented

- **Repository Pattern**: Clean separation of data access logic from business logic
- **Business Logic Layer**: Domain-specific certificate operations and business rules
- **Configuration Pattern**: Centralized configuration management with validation
- **Context Manager Pattern**: Resource management and initialization
- **Exception Hierarchy**: Structured error handling with specific error types

### Component Structure

```text
┌─────────────────────────────────────────────────────────────┐
│                    Certificate Class                        │
│               (ACME Protocol Handler)                       │
└──────────────────────┬──────────────────────────────────────┘
                       │
    ┌──────────────────┼──────────────────┐
    │                  │                  │
    ▼                  ▼                  ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────────┐
│Certificate      │ │Certificate      │ │CertificateManager   │
│Repository       │ │BusinessLogic    │ │(Business Logic)     │
│                 │ │                 │ │                     │
└─────────────────┘ └─────────────────┘ └─────────────────────┘
    │                  │                  │
    ▼                  ▼                  ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────────┐
│  DBstore        │ │CertificateData  │ │CAHandler            │
│                 │ │                 │ │                     │
└─────────────────┘ └─────────────────┘ └─────────────────────┘
```

## Core Components

### 1. Certificate Class (`/acme_srv/certificate.py`)

The `Certificate` class is the main entry point for certificate operations and ACME protocol handling. It provides methods for:

- Certificate issuance, renewal, and revocation
- CSR storage and validation
- Authorization and account checks
- Logging and audit
- Integration with CA handlers and hooks

#### Key Responsibilities

- Implements context manager for resource management
- Delegates data access to the repository layer
- Handles protocol-specific logic and error handling
- Coordinates with CAHandler for backend CA operations

### 2. Certificate Repository (`/acme_srv/db_handler.py`)

- Encapsulates all database operations related to certificates
- Provides methods for certificate CRUD, account checks, and order lookups
- Used by the `Certificate` class for persistent storage

### 3. Business Logic Layer (`/acme_srv/certificate_manager.py`)

- Implements higher-level certificate operations and business rules
- Handles certificate cleanup, expiry, and renewal logic
- Coordinates with repository and CAHandler

### 4. CA Handler (`/acme_srv/ca/ca_handler.py`)

- Abstracts backend CA operations (issuance, revocation, polling)
- Supports multiple CA backends via plugin architecture
- Used by the `Certificate` class for all CA interactions

### 5. Configuration and Helpers (`/acme_srv/helpers/`)

- Centralized configuration management (`config.py`)
- Certificate parsing, encoding, and utility functions
- Logging, error handling, and plugin loading

### 6. Error Handling

- Structured exception hierarchy for certificate operations
- Centralized error dictionary and logging
- Graceful handling of database and CA errors

## Extensibility

The certificate subsystem is designed for easy extension:

- Add new CA backends by implementing the CAHandler interface
- Extend business logic in `certificate_manager.py` for new workflows
- Add new certificate validation or parsing helpers in `/helpers/`
- Integrate with external systems via hooks

## Sequence Example: Certificate Issuance

```text
Client Request
     │
     ▼
Certificate.new_post() ──▶ Authorization/Account Check
     │
     ▼
  CAHandler.issuance()
     │
     ▼
Certificate._store_cert() ──▶ CertificateRepository.certificate_add()
     │
     ▼
  Logging/Audit
     │
     ▼
  Response to Client
```
