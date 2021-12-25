#!/usr/bin/python
""" database updater """
# pylint: disable=E0401, C0413
import sys
sys.path.insert(0, '..')
sys.path.insert(1, '.')
from acme_srv.helper import logger_setup  # nopep8
from acme_srv.db_handler import DBstore  # nopep8

if __name__ == '__main__':

    DEBUG = True

    # initialize logger
    LOGGER = logger_setup(DEBUG)

    # connect to database and do the upgrade
    DBSTORE = DBstore(DEBUG, LOGGER)
    DBSTORE.db_update()
