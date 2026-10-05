#!/usr/bin/python3
"""Unified DB schema updater for WSGI and Django backends.

CLI::

    a2c-schema-update [--mode {django,wsgi}]

When ``--mode`` is omitted, the handler is resolved from ``acme_srv.cfg`` /
``ACME_SRV_DB_HANDLER`` (same precedence as runtime).
"""

# pylint: disable=C0209, E0401, C0413
from __future__ import annotations

import argparse
import sys
import os
from typing import List, Optional

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir))
)

# Global variables to store imported modules (for testing)
django = None
call_command = None
Status = None
Housekeeping = None
__dbversion__ = None

STATUS_LIST = [
    "invalid",
    "pending",
    "ready",
    "processing",
    "valid",
    "expired",
    "deactivated",
    "revoked",
]


def setup_django() -> bool:
    """Setup Django and import required modules."""
    global django, call_command, Status, Housekeeping, __dbversion__

    try:
        from acme2certifier.acme_srv.helpers.django_boot import (
            configure_django_settings_module,
        )

        configure_django_settings_module()
        from acme2certifier.tools.a2c_django_deploy_env import load_deploy_env

        load_deploy_env()
        import django as django_module  # nopep8

        django = django_module
        django.setup()
        from django.core.management import call_command as django_call_command  # nopep8
        from acme2certifier.django_app.models import (
            Status as StatusModel,
            Housekeeping as HousekeepingModel,
        )  # nopep8
        from acme2certifier.acme_srv.version import (
            __dbversion__ as db_version,
        )  # nopep8

        call_command = django_call_command
        Status = StatusModel
        Housekeeping = HousekeepingModel
        __dbversion__ = db_version

        return True
    except ImportError as e:
        print(f"Error importing Django modules: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Error during Django setup: {e}", file=sys.stderr)
        return False


def run_migrations() -> bool:
    """Run Django migrations."""
    try:
        print("Running Django migrations...")
        call_command("makemigrations", interactive=False)
        print("Migrations created successfully.")

        call_command("migrate", interactive=False)
        print("Migrations applied successfully.")
        return True
    except Exception as e:
        print(f"Error during Django operations: {e}", file=sys.stderr)
        return False


def update_status_fields() -> bool:
    """Update status fields in the database."""
    exit_code = 0
    print("adding additional status fields to table...")

    for status in STATUS_LIST:
        try:
            _, _SCREATED = Status.objects.update_or_create(
                name=status, defaults={"name": status}
            )
        except Exception as e:
            print(f"Error updating status '{status}': {e}", file=sys.stderr)
            exit_code = 1

    return exit_code == 0


def update_db_version() -> bool:
    """Update database version."""
    try:
        print("update dbversion to {0}...".format(__dbversion__))
        _, _HCREATED = Housekeeping.objects.update_or_create(
            name="dbversion", defaults={"name": "dbversion", "value": __dbversion__}
        )
        print("Database version updated successfully.")
        return True
    except Exception as e:
        print(f"Error updating database version: {e}", file=sys.stderr)
        return False


def run_django_schema_update() -> int:
    """Run Django migrate + status seed + dbversion."""
    if not setup_django():
        return 1

    exit_code = 0

    if not run_migrations():
        exit_code = 1

    if not update_status_fields():
        exit_code = 1

    if not update_db_version():
        exit_code = 1

    if exit_code == 0:
        print("Django database update completed successfully.")
    else:
        print("Django database update completed with errors.", file=sys.stderr)

    return exit_code


def run_wsgi_schema_update() -> int:
    """Run WSGI/SQLite schema update via wsgi_handler.DBstore."""
    try:
        from acme2certifier.acme_srv.helper import logger_setup
        from acme2certifier.dbhandlers.wsgi_handler import DBstore

        debug = True
        logger = logger_setup(debug)
        dbstore = DBstore(debug, logger)
        dbstore.db_update()
        print("WSGI database update completed successfully.")
        return 0
    except Exception as e:
        print(f"Error during WSGI database update: {e}", file=sys.stderr)
        return 1


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Apply acme2certifier DB schema updates (WSGI or Django)."
    )
    parser.add_argument(
        "--mode",
        choices=("django", "wsgi"),
        default=None,
        help=(
            "DB backend to update. When omitted, requires an explicit "
            "[DBhandler] handler (or ACME_SRV_DB_HANDLER) of wsgi or django; "
            "does not fall back to the runtime default."
        ),
    )
    return parser.parse_args(argv)


def resolve_mode(mode: Optional[str] = None) -> Optional[str]:
    """Return ``django`` or ``wsgi``, or ``None`` when unset.

    Explicit ``--mode`` wins. Otherwise cfg/env must select wsgi or django;
    the runtime default (no handler configured) is not treated as an
    implicit schema-update target.
    """
    if mode in ("django", "wsgi"):
        return mode
    from acme2certifier.acme_srv.helpers.db_handler_select import (
        MODULE_TO_SHORT,
        resolve_db_handler,
    )

    module_path, source = resolve_db_handler()
    if source == "default":
        return None
    return MODULE_TO_SHORT.get(module_path)


def main(argv: Optional[List[str]] = None) -> int:
    """Dispatch schema update for the selected or resolved mode."""
    args = _parse_args(argv)
    mode = resolve_mode(args.mode)
    if mode is None:
        print(
            "WARNING: no explicit [DBhandler] handler (wsgi|django) in acme_srv.cfg "
            "and ACME_SRV_DB_HANDLER is unset or not wsgi/django. "
            "Skipping schema update. Set handler: wsgi or handler: django, "
            "or pass --mode wsgi|django.",
            file=sys.stderr,
        )
        return 0
    print(f"Running schema update (mode={mode})...")
    if mode == "django":
        return run_django_schema_update()
    return run_wsgi_schema_update()


if __name__ == "__main__":
    sys.exit(main())
