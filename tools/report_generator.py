#!/usr/bin/python
""" database updater """
# pylint: disable=E0401, C0413
import sys
sys.path.insert(0, '..')
sys.path.insert(1, '.')

from acme.helper import logger_setup
from acme.housekeeping import Housekeeping

if __name__ == '__main__':

    DEBUG = True

    # initialize logger
    LOGGER = logger_setup(DEBUG)

    with Housekeeping(DEBUG, LOGGER) as housekeeping:

        # certificate report in csv format
        report = housekeeping.certreport_get()
        # certificate report in json format
        report = housekeeping.certreport_get('json')
