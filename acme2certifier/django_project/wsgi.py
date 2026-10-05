"""
WSGI config for acme2certifier Django project.
"""

import os

from acme2certifier.acme_srv.helpers.django_boot import (
    configure_django_settings_module,
    prepend_sys_path_if_dir,
)

_PROJECT_HOME = os.environ.get("ACME2CERTIFIER_BASE_DIR", "/var/www/acme2certifier")
prepend_sys_path_if_dir(_PROJECT_HOME)
configure_django_settings_module()

from django.core.wsgi import get_wsgi_application  # noqa: E402

application = get_wsgi_application()
