#!/usr/bin/python
# -*- coding: utf-8 -*-
"""eab SQL handler"""

from __future__ import print_function

from logging import Logger
from typing import Dict, Optional

import pyodbc

from acme2certifier.acme_srv.helper import load_config
from acme2certifier.acme_srv.helpers.eab_profile import EabProfileMixin
from acme2certifier.eabhandlers.base import EABhandlerBase


class EABhandler(EABhandlerBase, EabProfileMixin):
    """EAB SQL handler"""

    def __init__(self, logger: Logger):
        super().__init__(logger)
        self.db_system = None
        self.db_host = None
        self.db_name = None
        self.db_user = None
        self.db_password = None

    def __enter__(self):
        """Makes EABhandler a Context Manager."""
        self._config_load()
        return self

    def _config_load(self):
        """Load database credentials from the EABhandler config section."""
        self.logger.debug("EABhandler._config_load()")
        config_dic = load_config(self.logger, "EABhandler")
        self.db_system = config_dic.get(
            "EABhandler", "db_system", fallback=self.db_system
        )
        self.db_host = config_dic.get("EABhandler", "db_host", fallback=self.db_host)
        self.db_name = config_dic.get("EABhandler", "db_name", fallback=self.db_name)
        self.db_user = config_dic.get("EABhandler", "db_user", fallback=self.db_user)
        self.db_password = config_dic.get(
            "EABhandler", "db_password", fallback=self.db_password
        )
        self.logger.debug("EABhandler._config_load() ended")

    def key_file_load(self) -> Dict[str, str]:
        """Load profiles from the eab credentials database."""
        self.logger.debug("EABhandler.key_file_load()")
        data_dic: Dict[str, str] = {}
        if self.db_host and self.db_name and self.db_user and self.db_password:
            sql_query = "SELECT key_id, profile FROM acme_credential WHERE enabled = 1;"
            db_driver = ""
            if self.db_system == "mssql":
                db_driver = "DRIVER={ODBC Driver 18 for SQL Server}"
            elif self.db_system == "postgres":
                db_driver = "DRIVER={PostgreSQL}"
            data_dic = self._load_profiles(db_driver, sql_query)
        self.logger.debug("EABhandler.key_file.load() ended: {%s}", bool(data_dic))
        return data_dic

    def _load_profiles(self, db_driver, sql_query: str) -> Dict[str, str]:
        """Load eab profiles from the database."""
        self.logger.debug("EABhandler._load_profiles()")
        data_dic: Dict[str, str] = {}
        try:
            conn_str = (
                db_driver
                + ";SERVER="
                + self.db_host
                + ";DATABASE="
                + self.db_name
                + ";UID="
                + self.db_user
                + ";PWD="
                + self.db_password
                + ";Encrypt=yes;TrustServerCertificate=yes"
            )
            conn = pyodbc.connect(conn_str)
            cursor = conn.cursor()
            cursor.execute(sql_query)
            rows = cursor.fetchall()
            for row in rows:
                data_dic[str(row[0])] = str(row[1])
        except Exception as err:
            self.logger.error("EABhandler._load_profiles() error: %s", err)
        return data_dic

    def mac_key_get(self, key_id: str) -> Optional[str]:
        """Look up the MAC key for an external account binding key_id."""
        self.logger.debug("EABhandler.mac_key_get(%s)", key_id)
        mac_key = None
        try:
            if (
                key_id
                and self.db_host
                and self.db_name
                and self.db_user
                and self.db_password
            ):
                data_dic = self.key_file_load()
                if key_id in data_dic:
                    mac_key = data_dic[key_id]
            else:
                self.logger.error("EABhandler.mac_key_get() error: key_id not found")
        except Exception as err:
            self.logger.error(
                "Failed to retrieve MAC key for key_id '%s': %s", key_id, err
            )
        self.logger.debug("EABhandler.mac_key_get() ended with %s", bool(mac_key))
        return mac_key
