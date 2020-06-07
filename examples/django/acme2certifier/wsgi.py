"""
WSGI config for acme2certifier project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/2.1/howto/deployment/wsgi/
"""
# pylint: disable=C0413
import os
import sys

PROJECT_HOME = '/var/www/acme2certifier'

if PROJECT_HOME not in sys.path:
    sys.path.append(PROJECT_HOME)

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'acme2certifier.settings')

from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
