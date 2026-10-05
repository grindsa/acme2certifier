#!/usr/bin/python
# -*- coding: utf-8 -*-
"""eab JSON file handler"""

from __future__ import print_function
import json
from typing import Dict

from acme2certifier.eabhandlers.base import KeyFileEABhandler


class EABhandler(KeyFileEABhandler):
    """EAB JSON file handler"""

    def key_file_load(self) -> Dict[str, str]:
        """Load kid -> mac mappings from a JSON key_file."""
        self.logger.debug("EABhandler.key_file_load()")
        data_dic: Dict[str, str] = {}
        if self.key_file:
            try:
                with open(self.key_file, encoding="utf8") as json_file:
                    data_dic = json.load(json_file)
            except Exception as err:
                self.logger.error("Failed to load EAB key file: %s", err)
        self.logger.debug("EABhandler.key_file_load() ended: %s", bool(data_dic))
        return data_dic
