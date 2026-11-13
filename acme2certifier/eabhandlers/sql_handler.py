#!/usr/bin/python
# -*- coding: utf-8 -*-
"""eab SQL handler"""

from __future__ import print_function

import json
from logging import Logger
from typing import Any, Dict, Optional

from acme2certifier.acme_srv.helper import load_config
from acme2certifier.acme_srv.helpers.eab_profile import EabProfileMixin
from acme2certifier.eabhandlers.base import EABhandlerBase

SQL_QUERY_NEW = "SELECT key_id, profile FROM acme_credential WHERE enabled = 1;"


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

    def key_file_load(self) -> Dict[str, Any]:
        """Load profiles from the eab credentials database."""
        self.logger.debug("EABhandler.key_file_load()")
        data_dic: Dict[str, Any] = {}
        if self.db_host and self.db_name and self.db_user and self.db_password:
            if self.db_system == "mssql":
                data_dic = self._load_mssql_profiles()
            elif self.db_system == "postgres":
                data_dic = self._load_postgres_profiles()
        self.logger.debug("EABhandler.key_file.load() ended: {%s}", bool(data_dic))
        return data_dic

    def _postgres_connect(self):
        """Open a PostgreSQL connection (lazy import)."""
        import psycopg2  # pylint: disable=import-outside-toplevel

        return psycopg2.connect(
            host=self.db_host,
            dbname=self.db_name,
            user=self.db_user,
            password=self.db_password,
        )

    def _mssql_connect(self):
        """Open an MSSQL connection via pyodbc (lazy import)."""
        import pyodbc  # pylint: disable=import-outside-toplevel

        conn_str = (
            "DRIVER={ODBC Driver 18 for SQL Server}"
            f";SERVER={self.db_host}"
            f";DATABASE={self.db_name}"
            f";UID={self.db_user}"
            f";PWD={self.db_password}"
            ";Encrypt=yes;TrustServerCertificate=yes"
        )
        return pyodbc.connect(conn_str)

    def _load_postgres_profiles(self) -> Dict[str, Any]:
        """Load eab profiles from PostgreSQL via psycopg2."""
        self.logger.debug("EABhandler._load_postgres_profiles()")
        data_dic: Dict[str, Any] = {}
        try:
            conn = self._postgres_connect()
            try:
                self._schema_ensure(conn, "postgres")
                cursor = conn.cursor()
                cursor.execute(SQL_QUERY_NEW)
                rows = cursor.fetchall()
                for row in rows:
                    key_id, profile = row
                    data_dic[str(key_id)] = self._profile_parse(profile)
            finally:
                conn.close()
        except Exception as err:
            self.logger.error("EABhandler._load_postgres_profiles() error: %s", err)
        return data_dic

    def _load_mssql_profiles(self) -> Dict[str, Any]:
        """Load eab profiles from MSSQL via pyodbc."""
        self.logger.debug("EABhandler._load_mssql_profiles()")
        data_dic: Dict[str, Any] = {}
        try:
            conn = self._mssql_connect()
            try:
                self._schema_ensure(conn, "mssql")
                cursor = conn.cursor()
                cursor.execute(SQL_QUERY_NEW)
                rows = cursor.fetchall()
                for row in rows:
                    key_id, profile = row
                    data_dic[key_id] = self._profile_parse(profile)
            finally:
                conn.close()
        except Exception as err:
            self.logger.error("EABhandler._load_mssql_profiles() error: %s", err)
        return data_dic

    def _profile_parse(self, profile: Any) -> Dict[str, Any]:
        """Parse a profile cell (JSON string or already-decoded dict)."""
        if isinstance(profile, dict):
            return profile
        if isinstance(profile, (bytes, bytearray)):
            profile = profile.decode("utf-8")
        return json.loads(profile)

    def _table_exists(self, conn, db_system: str, table_name: str) -> bool:
        """Return True if table_name exists in the connected database."""
        cursor = conn.cursor()
        if db_system == "postgres":
            cursor.execute(
                "SELECT to_regclass(%s) IS NOT NULL",
                (f"public.{table_name}",),
            )
            row = cursor.fetchone()
            return bool(row and row[0])
        cursor.execute(
            "SELECT OBJECT_ID(%s, 'U')",
            (f"dbo.{table_name}",),
        )
        row = cursor.fetchone()
        return bool(row and row[0] is not None)

    def _column_exists(
        self, conn, db_system: str, table_name: str, column_name: str
    ) -> bool:
        """Return True if column_name exists on table_name."""
        cursor = conn.cursor()
        if db_system == "postgres":
            cursor.execute(
                """
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = %s
                  AND column_name = %s
                """,
                (table_name, column_name),
            )
        else:
            cursor.execute(
                """
                SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = 'dbo'
                  AND TABLE_NAME = ?
                  AND COLUMN_NAME = ?
                """,
                (table_name, column_name),
            )
        return cursor.fetchone() is not None

    def _schema_ensure(self, conn, db_system: str) -> None:
        """Migrate legacy credentials/status schema when detected."""
        self.logger.debug("EABhandler._schema_ensure(%s)", db_system)
        has_new = self._table_exists(conn, db_system, "acme_credential")
        has_old = self._table_exists(conn, db_system, "credentials")

        if has_old and not has_new:
            self.logger.warning(
                "EAB SQL: legacy table 'credentials' detected; renaming to "
                "'acme_credential' and column 'status' to 'enabled'. "
                "Optional rename of parent table 'account' → 'acme_account' "
                "is not applied automatically; see docs/eab.md."
            )
            self._migrate_credentials_table(conn, db_system)
        elif has_new and self._column_exists(
            conn, db_system, "acme_credential", "status"
        ):
            if not self._column_exists(conn, db_system, "acme_credential", "enabled"):
                self.logger.warning(
                    "EAB SQL: legacy column 'status' on 'acme_credential' detected; "
                    "renaming to 'enabled'."
                )
                self._migrate_status_column(conn, db_system)

        conn.commit()

    def _migrate_credentials_table(self, conn, db_system: str) -> None:
        """Rename credentials → acme_credential and status → enabled if needed."""
        cursor = conn.cursor()
        if db_system == "postgres":
            cursor.execute("ALTER TABLE credentials RENAME TO acme_credential")
            if self._column_exists(conn, db_system, "acme_credential", "status"):
                cursor.execute(
                    "ALTER TABLE acme_credential RENAME COLUMN status TO enabled"
                )
        else:
            cursor.execute("EXEC sp_rename 'credentials', 'acme_credential'")
            if self._column_exists(conn, db_system, "acme_credential", "status"):
                cursor.execute(
                    "EXEC sp_rename 'acme_credential.status', 'enabled', 'COLUMN'"
                )

    def _migrate_status_column(self, conn, db_system: str) -> None:
        """Rename status → enabled on acme_credential."""
        cursor = conn.cursor()
        if db_system == "postgres":
            cursor.execute(
                "ALTER TABLE acme_credential RENAME COLUMN status TO enabled"
            )
        else:
            cursor.execute(
                "EXEC sp_rename 'acme_credential.status', 'enabled', 'COLUMN'"
            )

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
                    mac_key = data_dic[key_id]["hmac"]
            else:
                self.logger.error("EABhandler.mac_key_get() error: key_id not found")
        except Exception as err:
            self.logger.error(
                "Failed to retrieve MAC key for key_id '%s': %s", key_id, err
            )
        self.logger.debug("EABhandler.mac_key_get() ended with %s", bool(mac_key))
        return mac_key
