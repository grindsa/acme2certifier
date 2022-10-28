#!/usr/bin/python
# -*- coding: utf-8 -*-
""" eab json handler """
from __future__ import print_function
# pylint: disable=E0401
from acme_srv.helper import load_config


class EABhandler(object):
    """ EAB file handler """

    def __init__(self, logger=None):
        self.logger = logger
        self.key = None

    def __enter__(self):
        """ Makes EABhandler a Context Manager """
        if not self.key:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _config_load(self):
        """" load config from file """
        self.logger.debug('EABhandler._config_load()')

        config_dic = load_config(self.logger, 'EABhandler')
        if 'EABhandler' in config_dic and 'key' in config_dic['EABhandler']:
            self.key = config_dic['EABhandler']['key']

        self.logger.debug('EABhandler._config_load() ended')

    def mac_key_get(self, kid=None):
        """ check external account binding """
        self.logger.debug('EABhandler.mac_key_get({})'.format(kid))
        mac_key = None

        return mac_key
