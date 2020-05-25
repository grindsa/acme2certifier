#!/usr/bin/python
""" database updater """
import sys
sys.path.insert(0, '..')
sys.path.insert(1, '.')
from acme.helper import logger_setup
from acme.db_handler import DBstore

if __name__ == '__main__':

    DEBUG = True

    # initialize logger
    LOGGER = logger_setup(DEBUG)

    # connect to database and do the upgrade
    DBSTORE = DBstore(DEBUG, LOGGER)
    DBSTORE.db_update()
