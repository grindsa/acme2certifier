#!/usr/bin/python
# -*- coding: utf-8 -*-
"""eab kid-profile JSON/YAML handler"""

from __future__ import print_function
import json
import yaml

from acme2certifier.acme_srv.helpers.eab_profile import EabProfileMixin
from acme2certifier.eabhandlers.base import KeyFileEABhandler


class EABhandler(KeyFileEABhandler, EabProfileMixin):
    """EAB kid-profile handler"""

    def keyfile_content_load(self, key_file_content) -> dict:
        """Parse profiles from JSON or YAML key_file content."""
        self.logger.debug("EABhandler.keyfile_content_load()")
        try:
            profiles_dic = json.loads(key_file_content)
        except Exception as err:
            self.logger.error("Failed to parse key file content as JSON: %s", err)
            try:
                profiles_dic = yaml.safe_load(key_file_content)
            except Exception as err:
                self.logger.error("Failed to parse key file content as YAML: %s", err)
                profiles_dic = {}
        self.logger.debug(
            "EABhandler.keyfile_content_load() ended with %s", bool(profiles_dic)
        )
        return profiles_dic

    def key_file_load(self):
        """Load profiles from key_file."""
        self.logger.debug("EABhandler.key_file_load()")
        if self.key_file:
            try:
                with open(self.key_file, encoding="utf8") as key_file_content:
                    profiles_dic = self.keyfile_content_load(key_file_content.read())
            except Exception as err:
                self.logger.error("Failed to load key file: %s", err)
                profiles_dic = {}
        else:
            self.logger.error("No key_file specified for EAB profile loading.")
            profiles_dic = {}
        self.logger.debug(
            "EABhandler.key_file_load() ended with %s", bool(profiles_dic)
        )
        return profiles_dic

    def mac_key_get(self, kid: str = None) -> str:
        """Look up hmac for an external account binding kid."""
        self.logger.debug("EABhandler.mac_key_get(%s)", kid)
        mac_key = None
        try:
            if not kid:
                self.logger.warning("MAC key retrieval failed: kid=%s", kid)
            elif not self.key_file:
                self.logger.warning("MAC key retrieval failed: key_file is None")
            else:
                with open(self.key_file, encoding="utf8") as key_file_content:
                    data_dic = self.keyfile_content_load(key_file_content.read())
                    if kid in data_dic and "hmac" in data_dic[kid]:
                        mac_key = data_dic[kid]["hmac"]
                    elif kid in data_dic:
                        self.logger.warning(
                            "MAC key retrieval failed: kid=%s missing hmac in key file",
                            kid,
                        )
                    else:
                        self.logger.warning(
                            "MAC key retrieval failed: kid=%s not found in key file",
                            kid,
                        )
        except Exception as err:
            self.logger.error("Failed to retrieve MAC key for kid=%s: %s", kid, err)
        self.logger.debug("EABhandler.mac_key_get() ended with: %s", bool(mac_key))
        return mac_key
