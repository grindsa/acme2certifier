#!/usr/bin/env python3
"""Assert Django's live DATABASES['default'] session is TLS-encrypted."""

from __future__ import annotations

import os
import sys

# RPM/DEB layouts keep the package on PYTHONPATH, not in site-packages.
_APP_ROOTS = (
    "/opt/acme2certifier",
    "/var/www/acme2certifier",
)


def _prepare_runtime() -> None:
    """Make acme2certifier.django_project importable and set BASE_DIR."""
    os.environ.setdefault(
        "DJANGO_SETTINGS_MODULE", "acme2certifier.django_project.settings"
    )
    for root in _APP_ROOTS:
        django_project = os.path.join(root, "acme2certifier", "django_project")
        if not os.path.isdir(django_project):
            continue
        if root not in sys.path:
            sys.path.insert(0, root)
        os.environ.setdefault("ACME2CERTIFIER_BASE_DIR", root)
        return


def main() -> int:
    _prepare_runtime()
    import django

    django.setup()
    from django.db import connection

    vendor = connection.vendor
    with connection.cursor() as cursor:
        if vendor == "mysql":
            cursor.execute("SHOW STATUS LIKE 'Ssl_cipher'")
            row = cursor.fetchone()
            cipher = (row[1] if row else "") or ""
            if not str(cipher).strip():
                print(
                    "ERROR: Django MariaDB session is not TLS-encrypted "
                    "(Ssl_cipher empty)",
                    file=sys.stderr,
                )
                return 1
            print(f"Django MariaDB TLS cipher={cipher}")
            return 0
        if vendor == "postgresql":
            cursor.execute(
                "SELECT ssl, version, cipher FROM pg_stat_ssl "
                "WHERE pid = pg_backend_pid()"
            )
            row = cursor.fetchone()
            ssl_on = bool(row[0]) if row else False
            if not ssl_on:
                print(
                    "ERROR: Django PostgreSQL session is not TLS-encrypted "
                    f"(pg_stat_ssl={row!r})",
                    file=sys.stderr,
                )
                return 1
            print(
                f"Django PostgreSQL TLS ssl={row[0]} version={row[1]} "
                f"cipher={row[2]}"
            )
            return 0
    print(f"ERROR: unsupported Django DB vendor {vendor!r}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
