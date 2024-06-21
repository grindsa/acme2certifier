#!/usr/bin/python
# -*- coding: utf-8 -*-
""" eab file handler """
from __future__ import print_function
from typing import Dict
import csv
# pylint: disable=E0401
from acme_srv.helper import load_config


class EABhandler(object):
    """ EAB file handler """

    def __init__(self, logger: object = None):
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

    def key_file_load(self) -> Dict[str, str]:
        """ load key_file """
        self.logger.debug('EABhandler.key_file_load()')

        data_dic = {}
        if self.key_file:
            try:
                with open(self.key_file, mode='r', encoding='utf8') as csv_file:
                    csv_reader = csv.DictReader(csv_file)
                    for row in csv_reader:
                        data_dic[row['eab_kid']] = row['eab_mac']
            except Exception as err:
                self.logger.error('EABhandler.key_file_load() error: %s', err)

        self.logger.debug('EABhandler.key_file_load() ended: {%s}', bool(data_dic))
        return data_dic

    def mac_key_get(self, kid: str = None) -> str:
        """ check external account binding """
        self.logger.debug('EABhandler.mac_key_get(%s)', kid)

        mac_key = None
        if self.key_file and kid:
            data_dic = self.key_file_load()
            if kid in data_dic:
                mac_key = data_dic[kid]
            else:
                self.logger.error('EABhandler.mac_key_get() error: kid not found')
        self.logger.debug('EABhandler.mac_key_get() ended with: %s', bool(mac_key))
        return mac_key
