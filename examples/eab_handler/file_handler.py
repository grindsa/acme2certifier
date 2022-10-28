#!/usr/bin/python
# -*- coding: utf-8 -*-
""" eab file handler """
from __future__ import print_function
import csv
# pylint: disable=C0209, E0401
from acme_srv.helper import load_config


class EABhandler(object):
    """ EAB file handler """

    def __init__(self, logger=None):
        self.logger = logger
        self.key_file = None

    def __enter__(self):
        """ Makes EABhandler a Context Manager """
        if not self.key_file:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _config_load(self):
        """" load config from file """
        self.logger.debug('EABhandler._config_load()')

        config_dic = load_config(self.logger, 'EABhandler')
        if 'EABhandler' in config_dic and 'key_file' in config_dic['EABhandler']:
            self.key_file = config_dic['EABhandler']['key_file']

        self.logger.debug('EABhandler._config_load() ended')

    def mac_key_get(self, kid=None):
        """ check external account binding """
        self.logger.debug('EABhandler.mac_key_get({})'.format(kid))

        mac_key = None
        if self.key_file and kid:
            try:
                with open(self.key_file, mode='r', encoding='utf8') as csv_file:
                    csv_reader = csv.DictReader(csv_file)
                    for row in csv_reader:
                        if 'eab_kid' in row and 'eab_mac' in row and row['eab_kid'] == kid:
                            mac_key = row['eab_mac']
                            break
            except Exception as err:
                self.logger.error('EABhandler.mac_key_get() error: {0}'.format(err))

        self.logger.debug('EABhandler.mac_key_get() ended with: {0}'.format(bool(mac_key)))
        return mac_key
