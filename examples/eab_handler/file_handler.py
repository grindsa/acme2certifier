#!/usr/bin/python
# -*- coding: utf-8 -*-
""" skeleton for customized CA handler """
from __future__ import print_function
# pylint: disable=E0401
from acme.helper import load_config

class EABhandler(object):
    """ EAB file handler """

    def __init__(self, logger=None):
        self.logger = logger
        self.parameter = None

    def __enter__(self):
        """ Makes EABhandler a Context Manager """
        if not self.parameter:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _config_load(self):
        """" load config from file """
        self.logger.debug('EABhandler._config_load()')

        #config_dic = load_config(self.logger, 'EABhandler')
        #if 'parameter' in config_dic['EABhandler']:
        #    self.parameter = config_dic['EABhandler']['EABhandler']

        self.logger.debug('EABhandler._config_load() ended')

    def check(self, protected, payload):
        """ check external account binding """
        self.logger.debug('EABhandler.check()')

        from pprint import pprint
        pprint(protected)
        pprint(payload)

        code = 403
        message = 'joerns message'
        detail = 'joerns detail'

        self.logger.debug('EABhandler.check() ended with: {0}'.format(code))
        return (code, message, detail)
