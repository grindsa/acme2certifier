"""Django manage.py entry point for acme2certifier."""

import sys

from acme2certifier.acme_srv.helpers.django_boot import configure_django_settings_module


def main() -> None:
    """Run django-admin against packaged django_project settings."""
    configure_django_settings_module()
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
