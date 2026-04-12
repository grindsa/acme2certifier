<!-- markdownlint-disable MD013 -->

<!-- wiki-title Asynchronous Mode (`async_mode`) in acme2certifier -->

# Asynchronous Mode (`async_mode`) in acme2certifier

## Overview

`async_mode` is a configuration parameter that enables asynchronous processing for certificate enrollment and challenge validation in acme2certifier. Once enabled, certain operations (such as ACME challenge validation and certificate enrollment) are executed in background threads, allowing the API to respond immediately and process requests without blocking.

## Enabling `async_mode`

`async_mode` is enabled via the configuration file (typically `acme_srv.cfg`).

**Example configuration:**

```ini
[DEFAULT]
async_mode = True
```

### Requirements for Enabling

- **Database Handler:** You must use the [Django database handler](../examples/db_handler/django_handler.py) for asynchronous mode to work.
- **Database Backend:** The Django handler must be configured to use either a [MariaDB or PostgreSQL backend](external_database_support.md).

**Why Django Backend is Required:**

The Django backend is required for `async_mode` because it provides:

- More robust transaction management
- Connection pooling
- Thread safety
- **Concurrent write access**

These features are essential for reliable asynchronous operations. MariaDB and PostgreSQL, when used with Django's ORM, support concurrent access and atomic transactions, ensuring that background threads can safely read and write to the database without risking data corruption or race conditions. The default WSGI backend unfortuately lacks these guarantees, which can lead to unpredictable behavior or data loss in asynchronous workflows.

Hence, when using the WSGI-handler, `async_mode` will be ignored and the application will fall back to synchronous processing. The system logs a message if you attempt to enable async mode without the required backend:

> "asynchronous Challenge validation disabled, requires django db handler"
