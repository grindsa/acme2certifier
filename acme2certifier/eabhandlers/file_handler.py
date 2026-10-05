#!/usr/bin/python
# -*- coding: utf-8 -*-
"""eab CSV file handler"""

from __future__ import print_function
from typing import Dict
import csv

from acme2certifier.eabhandlers.base import KeyFileEABhandler


class EABhandler(KeyFileEABhandler):
    """EAB CSV file handler"""

    def key_file_load(self) -> Dict[str, str]:
        """Load kid -> mac mappings from a CSV key_file."""
        self.logger.debug("EABhandler.key_file_load()")
        data_dic: Dict[str, str] = {}
        if self.key_file:
            try:
                with open(self.key_file, mode="r", encoding="utf8") as csv_file:
                    csv_reader = csv.DictReader(csv_file)
                    for row in csv_reader:
                        data_dic[row["eab_kid"]] = row["eab_mac"]
            except Exception as err:
                self.logger.error("Failed to load EAB key file: %s", err)
        self.logger.debug("EABhandler.key_file_load() ended: {%s}", bool(data_dic))
        return data_dic
