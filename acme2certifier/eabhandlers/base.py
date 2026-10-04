# -*- coding: utf-8 -*-
"""Shared EAB handler context-manager and key-file helpers."""

from typing import Dict, Optional

# pylint: disable=E0401
from acme2certifier.acme_srv.helper import load_config


class EABhandlerBase(object):
    """Minimal EAB handler context manager."""

    def __init__(self, logger: object = None):
        self.logger = logger

    def __exit__(self, *args):
        """Close the connection at the end of the context."""


class KeyFileEABhandler(EABhandlerBase):
    """EAB handler that stores credentials in a configured key_file."""

    def __init__(self, logger: object = None):
        super().__init__(logger)
        self.key_file = None

    def __enter__(self):
        """Makes EABhandler a Context Manager."""
        if not self.key_file:
            self._config_load()
        return self

    def _config_load(self):
        """Load key_file from the EABhandler config section."""
        self.logger.debug("EABhandler._config_load()")
        config_dic = load_config(self.logger, "EABhandler")
        self.key_file = config_dic.get("EABhandler", "key_file", fallback=self.key_file)
        self.logger.debug("EABhandler._config_load() ended")

    def key_file_load(self) -> Dict[str, str]:
        """Load kid -> mac mappings. Subclasses implement the file format."""
        raise NotImplementedError

    def mac_key_get(self, kid: str = None) -> Optional[str]:
        """Look up the MAC key for an external account binding kid."""
        self.logger.debug("EABhandler.mac_key_get(%s)", kid)
        mac_key = None
        if not kid:
            self.logger.warning("MAC key retrieval failed: kid=%s", kid)
        elif not self.key_file:
            self.logger.warning("MAC key retrieval failed: key_file is None")
        else:
            data_dic = self.key_file_load()
            if kid in data_dic:
                mac_key = data_dic[kid]
            else:
                self.logger.warning(
                    "MAC key retrieval failed: kid=%s not found in key file", kid
                )
        self.logger.debug("EABhandler.mac_key_get() ended with: %s", bool(mac_key))
        return mac_key
