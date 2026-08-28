"""
WSGI config for acme2certifier Django project.
"""

import os
import sys

_PROJECT_HOME = os.environ.get("ACME2CERTIFIER_BASE_DIR", "/var/www/acme2certifier")
if os.path.isdir(_PROJECT_HOME) and _PROJECT_HOME not in sys.path:
    sys.path.insert(0, _PROJECT_HOME)

from acme2certifier.tools.a2c_django_deploy_env import load_deploy_env  # noqa: E402

load_deploy_env(_PROJECT_HOME if os.path.isdir(_PROJECT_HOME) else None)

os.environ.setdefault(
    "DJANGO_SETTINGS_MODULE", "acme2certifier.django_project.settings"
)

from django.core.wsgi import get_wsgi_application  # noqa: E402

application = get_wsgi_application()
