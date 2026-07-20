"""
WSGI config for acme2certifier Django project.
"""

from __future__ import annotations

import os
import sys

_PROJECT_HOME = os.environ.get("ACME2CERTIFIER_BASE_DIR", "/var/www/acme2certifier")
if os.path.isdir(_PROJECT_HOME) and _PROJECT_HOME not in sys.path:
    sys.path.insert(0, _PROJECT_HOME)

os.environ.setdefault(
    "DJANGO_SETTINGS_MODULE", "acme2certifier.django_project.settings"
)

from django.core.wsgi import get_wsgi_application  # noqa: E402

application = get_wsgi_application()
