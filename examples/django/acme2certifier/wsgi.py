"""
WSGI config for acme2certifier project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/2.1/howto/deployment/wsgi/
"""

import os
import sys

project_home = '/var/www/acme2certifier'

if project_home not in sys.path:
    sys.path.append(project_home)
    
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'acme2certifier.settings')

from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
