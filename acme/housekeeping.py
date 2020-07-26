#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Housekeeping class """
from __future__ import print_function
from acme.db_handler import DBstore
from acme.helper import load_config

class Housekeeping(object):
    """ Housekeeping class """
    def __init__(self, debug=None, logger=None):
        self.logger = logger
        self.dbstore = DBstore(debug, self.logger)

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _config_load(self):
        """" load config from file """
        self.logger.debug('_config_load()')
        config_dic = load_config()
        if 'Housekeeping' in config_dic:
            pass
