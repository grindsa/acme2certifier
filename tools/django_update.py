#!/usr/bin/python3
""" database updater """
# pylint: disable=E0401, C0413
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "acme2certifier.settings")
import django
django.setup()
from django.conf import settings
from acme_srv.models import Status, Housekeeping
from django.core.management import call_command
from acme_srv.version import __dbversion__

if __name__ == '__main__':

    call_command('makemigrations', interactive=False)
    call_command('migrate', interactive=False)

    # update status fields
    print('adding additional status fields to table...')
    STATUS_LIST = ['invalid', 'pending', 'ready', 'processing', 'valid', 'expired', 'deactivated', 'revoked']
    for status in STATUS_LIST:
        OBJ, _CREATED = Status.objects.update_or_create(name=status, defaults={'name': status})

    # update dbversion
    print('update dbversion to {0}...'.format(__dbversion__))
    OBJ, _CREATED = Housekeeping.objects.update_or_create(name='dbversion', defaults={'name': 'dbversion', 'value': __dbversion__})
