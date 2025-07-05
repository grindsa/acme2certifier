#!/usr/bin/python
# -*- coding: utf-8 -*-
"""eab json handler"""
from __future__ import print_function
import json
from typing import Dict

# pylint: disable=C0209, E0401
from acme_srv.helper import load_config


class EABhandler(object):
    """EAB file handler"""

    def __init__(self, logger: object = None):
        self.logger = logger
        self.key_file = None

    def __enter__(self):
        """Makes EABhandler a Context Manager"""
        if not self.key_file:
            self._config_load()
        return self

    def __exit__(self, *args):
        """cose the connection at the end of the context"""

    def _config_load(self):
        """ " load config from file"""
        self.logger.debug("EABhandler._config_load()")

        config_dic = load_config(self.logger, "EABhandler")
        self.key_file = config_dic.get("EABhandler", "key_file", fallback=self.key_file)

        self.logger.debug("EABhandler._config_load() ended")

    def key_file_load(self) -> Dict[str, str]:
        """load key_file"""
        self.logger.debug("EABhandler.key_file_load()")

        data_dic = {}
        if self.key_file:
            try:
                with open(self.key_file, encoding="utf8") as json_file:
                    data_dic = json.load(json_file)
            except Exception as err:
                self.logger.error("EABhandler.key_file_load() error: {0}".format(err))

        self.logger.debug(
            "EABhandler.key_file_load() ended: {0}".format(bool(data_dic))
        )
        return data_dic

    def mac_key_get(self, kid: str = None) -> str:
        """check external account binding"""
        self.logger.debug("EABhandler.mac_key_get({})".format(kid))
        mac_key = None

        data_dic = self.key_file_load()
        if kid and kid in data_dic:
            mac_key = data_dic[kid]

        self.logger.debug(
            "EABhandler.mac_key_get() ended with: {0}".format(bool(mac_key))
        )
        return mac_key
