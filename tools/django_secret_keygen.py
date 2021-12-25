#!/usr/bin/python3
""" secret key generator for django project """
# pylint: disable=E0401
from django.core.management.utils import get_random_secret_key
print(get_random_secret_key())  # lgtm [py/clear-text-logging-sensitive-data]
