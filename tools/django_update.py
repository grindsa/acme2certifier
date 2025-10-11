#!/usr/bin/python3
"""database updater"""
# pylint: disable=C0209, E0401, C0413
import sys
import os

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir))
)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "acme2certifier.settings")

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


def setup_django():
    """Setup Django and import required modules"""
    global django, call_command, Status, Housekeeping, __dbversion__

    try:
        import django as django_module  # nopep8

        django = django_module
        django.setup()
        from django.core.management import call_command as django_call_command  # nopep8
        from acme_srv.models import (
            Status as StatusModel,
            Housekeeping as HousekeepingModel,
        )  # nopep8
        from acme_srv.version import __dbversion__ as db_version  # nopep8

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


def run_migrations():
    """Run Django migrations"""
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


def update_status_fields():
    """Update status fields in the database"""
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


def update_db_version():
    """Update database version"""
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


def main():
    """Main function that orchestrates the database update process"""
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


if __name__ == "__main__":
    sys.exit(main())
