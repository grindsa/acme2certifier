"""Django manage.py entry point for acme2certifier."""

from __future__ import annotations

import os
import sys


def main() -> None:
    """Run django-admin against packaged django_project settings."""
    os.environ.setdefault(
        "DJANGO_SETTINGS_MODULE", "acme2certifier.django_project.settings"
    )
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Install with: pip install 'acme2certifier[django]'"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
