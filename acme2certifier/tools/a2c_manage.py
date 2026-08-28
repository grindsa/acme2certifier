"""Django manage.py entry point for acme2certifier."""

import os
import sys


def main() -> None:
    """Run django-admin against packaged django_project settings."""
    os.environ.setdefault(
        "DJANGO_SETTINGS_MODULE", "acme2certifier.django_project.settings"
    )
    from acme2certifier.tools.a2c_django_deploy_env import load_deploy_env

    load_deploy_env()
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Install with: pip install 'acme2certifier[django]'"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
