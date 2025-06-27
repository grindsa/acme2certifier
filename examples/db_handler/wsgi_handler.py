# pylint: disable=c0302, r0904, w0102
# -*- coding: utf-8 -*-
"""wsgi handler for acme2certifier"""
from __future__ import print_function
import sqlite3
import json
from typing import List, Tuple, Dict
import os

# pylint: disable=E0401
from acme_srv.helper import datestr_to_date, load_config
from acme_srv.version import __dbversion__


# Define constants
COLUMN_NOT_IN_TABLE_MSG = "column: %s not in %s table"


def initialize():
    """run db_handler specific initialization functions"""
    # pylint: disable=W0107
    pass


def dict_from_row(row):
    """small helper to convert the output of a "select" command into a dictionary"""
    return dict(zip(row.keys(), row))


class DBstore(object):
    """helper to do datebase operations"""

    def __init__(self, debug: bool = False, logger: object = None, db_name: str = None):
        """init"""
        self._column_cache = {}
        self.db_name = db_name
        self.debug = debug
        self.dbs = None
        self.cursor = None
        self.logger = logger

        if not self.db_name:
            cfg = load_config()
            if "DBhandler" in cfg and "dbfile" in cfg["DBhandler"]:
                db_name = cfg["DBhandler"]["dbfile"]
            else:
                db_name = os.path.dirname(__file__) + "/" + "acme_srv.db"

        self.db_name = db_name

        if not os.path.exists(self.db_name):
            self._db_create()

    def _columnnames_get(self, table: str) -> List[str]:
        """get columns of a table, with caching"""
        self.logger.debug("DBStore.columns_get(%s)", table)

        if table in self._column_cache:
            self.logger.debug("DBStore.columns_get(): cache hit for table %s", table)
            return self._column_cache[table]

        self._db_open()
        pre_statement = f"SELECT * from {table}"
        self.cursor.execute(pre_statement)
        result = [column[0] for column in self.cursor.description]
        self._db_close()
        self._column_cache[table] = result  # Cache the result

        self.logger.debug("DBStore.columns_get() ended with: %s elements", len(result))
        return result

    def _identifier_check(self, table: str, identifier: str) -> bool:
        """check if identifier is in table"""
        self.logger.debug("DBStore._identifier_check(%s, %s)", identifier, table)
        if "." in identifier:
            # we have a table.column name
            table, identifier = identifier.split(".", 1)
            self.logger.debug(
                "DBStore._identifier_check(): modified table/identifier to %s/%s",
                table,
                identifier,
            )
        elif "__" in identifier:
            # we have a table__column name
            table, identifier = identifier.split("__", 1)
            self.logger.debug(
                "DBStore._identifier_check(): modified table/identifier to %s/%s",
                table,
                identifier,
            )
        if table == "order":
            table = "orders"
            self.logger.debug(
                "DBStore._identifier_check(): modified table to %s", table
            )
        columnname_list = self._columnnames_get(table)
        result = True if identifier in columnname_list else False
        self.logger.debug("DBStore._identifier_check() ended with: %s", result)
        return result

    def _account_search(
        self, column: str, string: str, active: bool = True
    ) -> List[str]:
        """search account table for a certain key/value pair"""
        self.logger.debug("DBStore._account_search(%s, %s)", column, string)
        if not self._identifier_check("account", column):
            self.logger.warning(COLUMN_NOT_IN_TABLE_MSG, column, "account")
            return []
        self._db_open()
        try:
            if active:
                pre_statement = (
                    f"SELECT * from account WHERE {column} LIKE ? AND status_id = 5"
                )
            else:
                pre_statement = f"SELECT * from account WHERE {column} LIKE ?"
            self.cursor.execute(pre_statement, [string])
            result = self.cursor.fetchone()
        except Exception as err:
            self.logger.error(
                "DBStore._account_search(column:%s, pattern:%s) failed with err: %s",
                column,
                string,
                err,
            )
            result = []
        self._db_close()
        self.logger.debug("DBStore._account_search() ended with: %s", bool(result))
        return result

    def _authorization_search(self, column: str, string: str) -> List[str]:
        """search account table for a certain key/value pair"""
        self.logger.debug("DBStore._authorization_search(%s, %s)", column, string)

        if not self._identifier_check("authorization", column):
            self.logger.warning(COLUMN_NOT_IN_TABLE_MSG, column, "authorization")
            return []
        if column == "name":
            self.logger.debug("rename name to authorization.name")
            column = "authorization.name"
        self._db_open()
        pre_statement = f"""SELECT
                            authorization.*,
                            orders.id as orders__id,
                            orders.name as order__name,
                            status.id as status_id,
                            status.name as status__name,
                            account.name as order__account__name
                        from authorization
                        LEFT JOIN orders on orders.id = authorization.order_id
                        LEFT JOIN status on status.id = authorization.status_id
                        LEFT JOIN account on account.id = orders.account_id
                        WHERE {column} LIKE ?"""
        try:
            self.cursor.execute(pre_statement, [string])
            result = self.cursor.fetchall()
        except Exception as err:
            self.logger.error(
                "DBStore._authorization_search(column:%s, pattern:%s) failed with err: %s",
                column,
                string,
                err,
            )
            result = []
        self._db_close()
        self.logger.debug("DBStore._authorization_search() ended")
        return result

    def _cahandler_search(self, column: str, string: str) -> List[str]:
        """search cahandler table for a certain key/value pair"""
        self.logger.debug("DBStore._cahandler_search(%s, %s)", column, string)

        if not self._identifier_check("cahandler", column):
            self.logger.warning(COLUMN_NOT_IN_TABLE_MSG, column, "cahandler")
            return []
        self._db_open()
        pre_statement = f"""SELECT cahandler.* from cahandler WHERE {column} LIKE ?"""
        try:
            self.cursor.execute(pre_statement, [string])
            result = self.cursor.fetchone()
        except Exception as err:
            self.logger.error(
                "DBStore._cahandler_search(column:%s, pattern:%s) failed with err: %s",
                column,
                string,
                err,
            )
            result = None
        self._db_close()
        self.logger.debug("DBStore._cahandler_search() ended")
        return result

    def _certificate_account_check(
        self,
        account_name: str,
        certificate_dic: Dict[str, str],
        order_dic: Dict[str, str],
    ) -> List[str]:
        self.logger.debug("DBStore._certificate_account_check(%s)", account_name)
        result = None
        if account_name:
            # if there is an acoount name validate it against the account_name from db-query
            if order_dic["account__name"] == account_name:
                result = certificate_dic["order__name"]
                self.logger.debug("message signed with account key")
            else:
                self.logger.debug("account_name and and account_name from oder differ.")
        else:
            # no account name given (message signed with domain key)
            result = certificate_dic["order__name"]
            self.logger.debug("message signed with domain key")
        self.logger.debug("DBStore._certificate_account_check() ended with: %s", result)
        return result

    def _certificate_insert(self, data_dic: Dict[str, str]) -> int:
        """insert certificate"""
        self.logger.debug("_certificate_insert() for %s", data_dic["name"])
        # change order name to id but tackle cases where we cannot do this
        try:
            data_dic["order"] = dict_from_row(
                self._order_search("name", data_dic["order"])
            )["id"]
        except Exception:
            data_dic["order"] = 0

        self._db_open()
        if "csr" not in data_dic:
            data_dic["csr"] = ""
        if "header_info" not in data_dic:
            data_dic["header_info"] = ""
        if "error" in data_dic:
            self.cursor.execute(
                """INSERT INTO Certificate(name, error, order_id, csr, header_info) VALUES(:name, :error, :order, :csr, :header_info)""",
                data_dic,
            )
        else:
            self.cursor.execute(
                """INSERT INTO Certificate(name, csr, order_id, header_info) VALUES(:name, :csr, :order, :header_info)""",
                data_dic,
            )
        self._db_close()
        self.logger.debug("insert new entry for %s", data_dic["name"])

        rid = self.cursor.lastrowid
        self.logger.debug("_certificate_insert() ended with: %s", rid)
        return rid

    def _certificate_update(
        self, data_dic: Dict[str, str], exists: Dict[str, str]
    ) -> int:
        self.logger.debug(
            "_certificate_update() for %s id:%s",
            data_dic["name"],
            dict_from_row(exists)["id"],
        )
        self._db_open()
        if "error" in data_dic:
            self.cursor.execute(
                """UPDATE Certificate SET error = :error, poll_identifier = :poll_identifier WHERE name = :name""",
                data_dic,
            )
        else:
            if "expire_uts" not in data_dic:
                data_dic["expire_uts"] = 0
            if "issue_uts" not in data_dic:
                data_dic["issue_uts"] = 0
            if "replaced" not in data_dic:
                data_dic["replaced"] = exists["replaced"]

            self.cursor.execute(
                """UPDATE Certificate SET cert = :cert, cert_raw = :cert_raw, issue_uts = :issue_uts, expire_uts = :expire_uts, renewal_info = :renewal_info, poll_identifier = :poll_identifier, replaced = :replaced, header_info = :header_info, serial = :serial, aki = :aki WHERE name = :name""",
                data_dic,
            )
        self._db_close()
        rid = dict_from_row(exists)["id"]
        self.logger.debug("_certificate_update() ended with: %s", rid)
        return rid

    def _certificate_search(self, column: str, string: str) -> Dict[str, str]:
        """search certificate table for a certain key/value pair"""
        self.logger.debug("DBStore._certificate_search(%s, %s)", column, string)
        if not self._identifier_check("certificate", column):
            self.logger.warning(COLUMN_NOT_IN_TABLE_MSG, column, "certificate")
            return {}
        self._db_open()
        if column != "order__name":
            column = f"certificate.{column}"
            self.logger.debug(f"modified column to {column}")
        pre_statement = f"""SELECT certificate.*,
                            orders.id as order__id,
                            orders.name as order__name,
                            orders.status_id as order__status_id,
                            account.name as order__account__name,
                            account.eab_kid as order__account__eab_kid
                            from certificate
                            INNER JOIN orders on orders.id = certificate.order_id
                            INNER JOIN account on account.id = orders.account_id
                            WHERE {column} LIKE ?"""
        self.cursor.execute(pre_statement, [string])
        result = self.cursor.fetchone()
        self._db_close()
        self.logger.debug("DBStore._certificate_search() ended with: %s", bool(result))
        return result

    def _challenge_search(self, column: str, string: str) -> List[str]:
        """search challenge table for a certain key/value pair"""
        self.logger.debug("DBStore._challenge_search(%s, %s)", column, string)

        if not self._identifier_check("challenge", column):
            self.logger.warning(COLUMN_NOT_IN_TABLE_MSG, column, "challenge")
            return []
        self._db_open()
        pre_statement = f"""
            SELECT
                challenge.*,
                status.id as status__id,
                status.name as status__name,
                authorization.id as authorization__id,
                authorization.name as authorization__name,
                authorization.type as authorization__type,
                authorization.value as authorization__value,
                authorization.token as authorization__token,
                orders.name as authorization__order__name,
                account.name as authorization__order__account__name
            from challenge
            INNER JOIN status on status.id = challenge.status_id
            INNER JOIN authorization on authorization.id = challenge.authorization_id
            INNER JOIN orders on orders.id = authorization.order_id
            INNER JOIN account on account.id = orders.account_id
            WHERE challenge.{column} LIKE ?"""
        try:
            self.cursor.execute(pre_statement, [string])
            result = self.cursor.fetchone()
        except Exception as err:
            self.logger.error(
                "DBStore._challenge_search(column:%s, pattern:%s) failed with err: %s",
                column,
                string,
                err,
            )
            result = []
        self._db_close()
        self.logger.debug("DBStore._challenge_search() ended")
        return result

    def _cliaccount_search(self, column: str, string: str) -> Dict[str, str]:
        """search account table for a certain key/value pair"""
        self.logger.debug("DBStore._cliaccount_search(%s, %s)", column, string)

        if not self._identifier_check("cliaccount", column):
            self.logger.warning(COLUMN_NOT_IN_TABLE_MSG, column, "cliaccount")
            return {}
        self._db_open()
        try:
            pre_statement = f"SELECT * from cliaccount WHERE {column} LIKE ?"
            self.cursor.execute(pre_statement, [string])
            result = self.cursor.fetchone()
        except Exception as err:
            self.logger.error(
                "DBStore._cliaccount_search(column:%s, pattern:%s) failed with err: %s",
                column,
                string,
                err,
            )
            result = None
        self._db_close()
        self.logger.debug("DBStore._account_search() ended with: %s", bool(result))
        return result

    def _db_close(self):
        """commit and close"""
        # self.logger.debug('DBStore._db_close()')
        self.dbs.commit()
        self.dbs.close()
        # self.logger.debug('DBStore._db_close() ended')

    def _db_create(self):
        """create the database if dos not exist"""
        self.logger.debug("DBStore._db_create(%s)", self.db_name)
        self._db_open()
        # create status table
        self.logger.debug("create status")
        self.cursor.execute(
            """
            CREATE TABLE "status" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(15) UNIQUE NOT NULL)
        """
        )
        insert_status_statement = """INSERT INTO status(name) VALUES(:name)"""
        self.cursor.execute(insert_status_statement, {"name": "invalid"})
        self.cursor.execute(insert_status_statement, {"name": "pending"})
        self.cursor.execute(insert_status_statement, {"name": "ready"})
        self.cursor.execute(insert_status_statement, {"name": "processing"})
        self.cursor.execute(insert_status_statement, {"name": "valid"})
        self.cursor.execute(insert_status_statement, {"name": "expired"})
        self.cursor.execute(insert_status_statement, {"name": "deactivated"})
        self.cursor.execute(insert_status_statement, {"name": "revoked"})
        # create nonce table
        self.logger.debug("create nonce")
        self.cursor.execute(
            """
            CREATE TABLE "nonce" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "nonce" varchar(30) NOT NULL, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
        """
        )
        self.logger.debug("create account")
        self.cursor.execute(
            """
            CREATE TABLE "account" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(15) NOT NULL UNIQUE, "alg" varchar(10) NOT NULL, "jwk" TEXT UNIQUE NOT NULL, "contact" TEXT NOT NULL, "eab_kid" varchar(255) DEFAULT \'\', "status_id" integer NOT NULL REFERENCES "status" ("id") DEFAULT 5, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
        """
        )
        self.logger.debug("create cliaccount")
        self.cursor.execute(
            """
            CREATE TABLE "cliaccount" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(15) NOT NULL UNIQUE, "jwk" TEXT UNIQUE NOT NULL, "contact" TEXT NOT NULL, "cliadmin" INT, "reportadmin" INT, "certificateadmin" INT, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
        """
        )
        self.logger.debug("create orders")
        self.cursor.execute(
            """
            CREATE TABLE "orders" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(15) UNIQUE NOT NULL, "notbefore" integer DEFAULT 0, "notafter" integer DEFAULT 0, "identifiers" text NOT NULL, "account_id" integer NOT NULL REFERENCES "account" ("id"), "status_id" integer NOT NULL REFERENCES "status" ("id") DEFAULT 2, "expires" integer NOT NULL, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
        """
        )
        self.logger.debug("create authorization")
        self.cursor.execute(
            """
            CREATE TABLE "authorization" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(15) NOT NULL UNIQUE, "order_id" integer NOT NULL REFERENCES "order" ("id"), "type" varchar(5) NOT NULL, "value" text NOT NULL, "expires" integer, "token" varchar(64), "status_id" integer NOT NULL REFERENCES "status" ("id") DEFAULT 2, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
        """
        )
        self.logger.debug("create challenge")
        self.cursor.execute(
            """
            CREATE TABLE "challenge" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(15) NOT NULL UNIQUE, "token" varchar(64), "authorization_id" integer NOT NULL REFERENCES "authorization" ("id"), "expires" integer, "type" varchar(15) NOT NULL, "keyauthorization" varchar(128), "status_id" integer NOT NULL REFERENCES "status" ("id"), "validated" integer DEFAULT 0, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
        """
        )
        self.logger.debug("create certificate")
        self.cursor.execute(
            """
            CREATE TABLE "certificate" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(15) NOT NULL UNIQUE, "cert" text, "cert_raw" text, "error" text, "order_id" integer NOT NULL REFERENCES "order" ("id"), "csr" text NOT NULL, "poll_identifier" text,  "header_info" text, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, "renewal_info" text, "aki" text, "serial" text, "issue_uts" integer DEFAULT 0, "expire_uts" integer DEFAULT 0, "replaced" bolean DEFAULT 0)
        """
        )
        self.cursor.execute(
            """
            CREATE TABLE "housekeeping" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(30) NOT NULL UNIQUE, "value" text, "modified_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
        """
        )
        self.cursor.execute(
            """
            CREATE TRIGGER [UpdateLastTime]
                AFTER
                UPDATE
                ON housekeeping
                FOR EACH ROW
                WHEN NEW.modified_at <= OLD.modified_at
            BEGIN
                update housekeeping set modified_at=CURRENT_TIMESTAMP where id=OLD.id;
            END
        """
        )

        self.cursor.execute(
            f"""INSERT OR IGNORE INTO housekeeping (name, value) VALUES ("dbversion", "{__dbversion__}")"""
        )
        self.cursor.execute(
            """
            CREATE TABLE "cahandler" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(15) NOT NULL UNIQUE, "value1" text, "value2" text, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
        """
        )
        self._db_close()
        self.logger.debug("DBStore._db_create() ended")

    def _db_open(self):
        """opens db and sets cursor"""
        self.dbs = sqlite3.connect(self.db_name)
        self.dbs.row_factory = sqlite3.Row
        self.cursor = self.dbs.cursor()

    def _db_update_account(self):
        """update account table"""
        self.logger.debug("DBStore._db_update_account()")

        # add eab_kid
        self.cursor.execute("""PRAGMA table_info(account)""")
        account_column_list = []
        for column in self.cursor.fetchall():
            account_column_list.append(column[1])
        if "eab_kid" not in account_column_list:
            self.logger.info("alter account table - add eab_kid")
            self.cursor.execute(
                """ALTER TABLE account ADD COLUMN eab_kid varchar(255) DEFAULT \'\'"""
            )
        if "status_id" not in account_column_list:
            self.logger.info("alter account table - add status_id")
            self.cursor.execute(
                """ALTER TABLE account ADD COLUMN status_id integer NOT NULL REFERENCES status(id) DEFAULT 5"""
            )

    def _db_update_authorization(self):
        """alter orders table"""
        self.logger.debug("DBStore._db_update_authorization()")

        # change identifier field to text to remove length restriction
        self.cursor.execute("""PRAGMA table_info(authorization)""")
        for column in self.cursor.fetchall():
            if column[1] == "value" and "varchar" in column[2].lower():
                self.logger.info(
                    "alter authorization table - change value field type to TEXT"
                )
                self.cursor.execute("""ALTER TABLE authorization RENAME TO tmp""")
                self.cursor.execute(
                    """
                    CREATE TABLE "authorization" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(15) NOT NULL UNIQUE, "order_id" integer NOT NULL REFERENCES "order" ("id"), "type" varchar(5) NOT NULL, "value" text NOT NULL, "expires" integer, "token" varchar(64), "status_id" integer NOT NULL REFERENCES "status" ("id") DEFAULT 2, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
                """
                )
                self.cursor.execute(
                    """INSERT INTO authorization(id, name, order_id, type, value, expires, token, status_id, created_at) SELECT id, name, order_id, type, value, expires, token, status_id, created_at  FROM tmp"""
                )
                self.cursor.execute("""DROP TABLE tmp""")

    def _db_update_cahandler(self):
        """alter cahandler table"""
        self.logger.debug("DBStore._db_update_cahandler()")

        self.cursor.execute(
            "SELECT count(*) from sqlite_master where type='table' and name='cahandler'"
        )
        if self.cursor.fetchone()[0] != 1:
            self.logger.info("create cahandler table")
            self.cursor.execute(
                """
                CREATE TABLE "cahandler" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(15) NOT NULL UNIQUE, "value1" text, "value2" text, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
            """
            )

    def _db_update_certificate(self):
        """alter certificate table"""
        self.logger.debug("DBStore._db_update_certificate()")

        # add poll_identifier if not existing
        self.cursor.execute("""PRAGMA table_info(certificate)""")
        certificate_column_list = []
        for column in self.cursor.fetchall():
            certificate_column_list.append(column[1])
        if "poll_identifier" not in certificate_column_list:
            self.logger.info("alter certificate table - add poll_identifier")
            self.cursor.execute(
                """ALTER TABLE certificate ADD COLUMN poll_identifier text"""
            )
        if "issue_uts" not in certificate_column_list:
            self.logger.info("alter certificate table - add issue_uts")
            self.cursor.execute(
                """ALTER TABLE certificate ADD COLUMN issue_uts integer DEFAULT 0"""
            )
        if "expire_uts" not in certificate_column_list:
            self.logger.info("alter certificate table - add expire_uts")
            self.cursor.execute(
                """ALTER TABLE certificate ADD COLUMN expire_uts integer DEFAULT 0"""
            )
        if "renewal_info" not in certificate_column_list:
            self.logger.info("alter certificate table - add renewal_info")
            self.cursor.execute(
                """ALTER TABLE certificate ADD COLUMN renewal_info text"""
            )
        if "replaced" not in certificate_column_list:
            self.logger.info("alter certificate table - add replaced")
            self.cursor.execute(
                """ALTER TABLE certificate ADD COLUMN replaced boolean DEFAULT 0"""
            )
        if "header_info" not in certificate_column_list:
            self.logger.info("alter certificate table - add header_info")
            self.cursor.execute(
                """ALTER TABLE certificate ADD COLUMN header_info text"""
            )
        if "aki" not in certificate_column_list:
            self.logger.info("alter certificate table - add aki")
            self.cursor.execute("""ALTER TABLE certificate ADD COLUMN aki text""")
        if "serial" not in certificate_column_list:
            self.logger.info("alter certificate table - add serial")
            self.cursor.execute("""ALTER TABLE certificate ADD COLUMN serial text""")

    def _db_update_challenge(self):
        """alter challenge table"""
        self.logger.debug("DBStore._db_update_certificate()")

        self.cursor.execute("""PRAGMA table_info(challenge)""")
        challenges_column_list = []
        for column in self.cursor.fetchall():
            challenges_column_list.append(column[1])

        if "validated" not in challenges_column_list:
            self.logger.info("alter challenge table - add validated")
            self.cursor.execute(
                """ALTER TABLE challenge ADD COLUMN validated integer DEFAULT 0"""
            )

    def _db_update_cliaccount(self):
        """alter cliaccount table"""
        self.logger.debug("DBStore._db_update_cliaccount()")

        self.cursor.execute(
            "SELECT count(*) from sqlite_master where type='table' and name='cliaccount'"
        )
        if self.cursor.fetchone()[0] != 1:
            self.logger.info("create cliaccount table")
            self.cursor.execute(
                """
                CREATE TABLE "cliaccount" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(15) NOT NULL UNIQUE, "jwk" TEXT UNIQUE NOT NULL, "contact" TEXT NOT NULL, "cliadmin" INT, "reportadmin" INT, "certificateadmin" INT, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
            """
            )

    def _db_update_housekeeping(self):
        """alter housekeeping table"""
        self.logger.debug("DBStore._db_update_housekeeping()")

        # housekeeping table
        self.cursor.execute(
            "SELECT count(*) from sqlite_master where type='table' and name='housekeeping'"
        )
        if self.cursor.fetchone()[0] != 1:
            self.logger.info("create housekeeping table and trigger")
            self.cursor.execute(
                """
                CREATE TABLE "housekeeping" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(30) NOT NULL UNIQUE, "value" text, "modified_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
            """
            )
            self.cursor.execute(
                """
                CREATE TRIGGER [UpdateLastTime]
                    AFTER
                    UPDATE
                    ON housekeeping
                    FOR EACH ROW
                    WHEN NEW.modified_at <= OLD.modified_at
                BEGIN
                    update housekeeping set modified_at=CURRENT_TIMESTAMP where id=OLD.id;
                END
            """
            )
        else:
            self.cursor.execute("""PRAGMA table_info(housekeeping)""")
            for column in self.cursor.fetchall():
                if (
                    column[1] == "name" and column[2].lower() == "varchar(15)"
                ):  # pragma: no cover
                    self.logger.info(
                        "alter housekeeping table  - change size of the name field to 30"
                    )  # pragma: no cover
                    self.cursor.execute(
                        """ALTER TABLE housekeeping RENAME TO tmp_hk"""
                    )  # pragma: no cover
                    self.cursor.execute(
                        """
                        CREATE TABLE "housekeeping" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(30) NOT NULL UNIQUE, "value" text, "modified_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
                    """
                    )  # pragma: no cover
                    self.cursor.execute(
                        """INSERT INTO housekeeping(id, name, value, modified_at) SELECT id, name, value, modified_at  FROM tmp_hk"""
                    )  # pragma: no cover
                    self.cursor.execute("""DROP TABLE tmp_hk""")  # pragma: no cover

    def _db_update_orders(self):
        """alter orders table"""
        self.logger.debug("DBStore._db_update_orders()")

        # change identifier field to text to remove length restriction
        self.cursor.execute("""PRAGMA table_info(orders)""")
        for column in self.cursor.fetchall():
            if column[1] == "identifiers" and "varchar" in column[2].lower():
                self.logger.info(
                    "alter order table - change identifier field type to TEXT"
                )
                self.cursor.execute("""ALTER TABLE orders RENAME TO tmp""")
                self.cursor.execute(
                    """
                    CREATE TABLE "orders" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(15) UNIQUE NOT NULL, "notbefore" integer DEFAULT 0, "notafter" integer DEFAULT 0, "identifiers" text NOT NULL, "account_id" integer NOT NULL REFERENCES "account" ("id"), "status_id" integer NOT NULL REFERENCES "status" ("id") DEFAULT 2, "expires" integer NOT NULL, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
                """
                )
                self.cursor.execute(
                    """INSERT INTO orders(id, name, notbefore, notafter, identifiers, account_id, status_id, expires, created_at) SELECT id, name, notbefore, notafter, identifiers, account_id, status_id, expires, created_at  FROM tmp"""
                )
                self.cursor.execute("""DROP TABLE tmp""")

    def _db_update_status(self):
        """update status table"""
        self.logger.debug("DBStore._db_update_status()")

        # add additional values to status table
        pre_statement = "SELECT * from status WHERE status.name LIKE ?"
        self.cursor.execute(pre_statement, ["deactivated"])
        if not self.cursor.fetchone():
            self.logger.info("adding additional status")
            insert_status_statement = """INSERT INTO status(name) VALUES(:name)"""
            self.cursor.execute(insert_status_statement, {"name": "expired"})
            self.cursor.execute(insert_status_statement, {"name": "deactivated"})
            self.cursor.execute(insert_status_statement, {"name": "revoked"})

    def _order_search(self, column: str, string: str) -> List[str]:
        """search order table for a certain key/value pair"""
        self.logger.debug("DBStore._order_search(%s, %s)", column, string)

        if not self._identifier_check("orders", column):
            self.logger.warning(COLUMN_NOT_IN_TABLE_MSG, column, "orders")
            return []
        self._db_open()
        pre_statement = f"""
                    SELECT
                        orders.*,
                        status.name as status__name,
                        status.id as status__id,
                        account.name as account__name,
                        account.id as account_id
                    from orders
                    INNER JOIN status on status.id = orders.status_id
                    INNER JOIN account on account.id = orders.account_id
                    WHERE orders.{column} LIKE ?"""
        try:
            self.cursor.execute(pre_statement, [string])
            result = self.cursor.fetchone()
        except Exception as err:
            self.logger.error(
                "DBStore._order_search(column:%s, pattern:%s) failed with err: %s",
                column,
                string,
                err,
            )
            result = []
        self._db_close()
        self.logger.debug("DBStore._order_search() ended")
        return result

    def _status_search(self, column: str, string: str) -> Tuple[int, str]:
        """search status table for a certain key/value pair"""
        self.logger.debug("DBStore._status_search(%s, %s)", column, string)

        if not self._identifier_check("status", column):
            self.logger.warning(COLUMN_NOT_IN_TABLE_MSG, column, "status")
            return (None, None)
        self._db_open()
        pre_statement = f"SELECT * from status WHERE status.{column} LIKE ?"
        self.cursor.execute(pre_statement, [string])
        result = self.cursor.fetchone()
        self._db_close()
        self.logger.debug("DBStore._status_search() ended")
        return result

    def account_add(self, data_dic):
        """add account in database"""
        self.logger.debug("DBStore.account_add(%s)", data_dic)

        # add eab_kid field if not existing
        if "eab_kid" not in data_dic:
            data_dic["eab_kid"] = ""

        # we need this for compability with django
        created = False
        # check if we alredy have an entry for the key
        exists = self._account_search("jwk", data_dic["jwk"])
        self._db_open()
        if bool(exists):
            # update
            aname = exists[1]
            self.logger.debug("account exists: %s id: %s", aname, exists[0])
            self.cursor.execute(
                """UPDATE ACCOUNT SET alg = :alg, jwk = :jwk, contact = :contact WHERE jwk = :jwk""",
                data_dic,
            )
        else:
            # insert
            self.cursor.execute(
                """INSERT INTO ACCOUNT(alg, jwk, contact, name, eab_kid) VALUES(:alg, :jwk, :contact, :name, :eab_kid)""",
                data_dic,
            )
            aname = data_dic["name"]
            created = True

        self._db_close()
        self.logger.debug("DBStore.account_add() ended")
        return (aname, created)

    def account_delete(self, aname: str) -> bool:
        """add account in database"""
        self.logger.debug("DBStore.account_delete(%s)", aname)
        self._db_open()
        pre_statement = "DELETE FROM account WHERE name LIKE ?"
        self.cursor.execute(pre_statement, [aname])
        result = bool(self.cursor.rowcount)
        self._db_close()
        self.logger.debug("DBStore.account_delete() ended")
        return result

    def account_lookup(
        self,
        column: str,
        string: str,
        vlist: List = None,  # pylint: disable=unused-argument NOSONAR
    ) -> Dict[str, str]:
        """lookup account table for a certain key/value pair and return id"""
        self.logger.debug(
            "DBStore.account_lookup(column:%s, pattern:%s)", column, string
        )
        try:
            result = dict_from_row(self._account_search(column, string))
        except Exception as _err:
            result = {}
        if "created_at" in result:
            result["created_at"] = datestr_to_date(
                result["created_at"], "%Y-%m-%d %H:%M:%S"
            )
        self.logger.debug("DBStore.account_lookup() ended")
        return result

    def account_update(
        self, data_dic: Dict[str, str], active: bool = True
    ) -> List[str]:
        """update existing account"""
        self.logger.debug("DBStore.account_update(%s)", data_dic)

        try:
            lookup = dict_from_row(self._account_search("name", data_dic["name"]))
        except Exception as _err:
            lookup = None

        if lookup:
            if "alg" not in data_dic:
                data_dic["alg"] = lookup["alg"]
            if "contact" not in data_dic:
                data_dic["contact"] = lookup["contact"]
            if "jwk" not in data_dic:
                data_dic["jwk"] = lookup["jwk"]
            if "status_id" not in data_dic:
                data_dic["status_id"] = lookup["status_id"]
            self._db_open()
            self.cursor.execute(
                """UPDATE account SET alg = :alg, contact = :contact, jwk = :jwk, status_id = :status_id WHERE name = :name""",
                data_dic,
            )
            if active:
                self.cursor.execute(
                    """SELECT id FROM account WHERE name=:name AND status_id = 5""",
                    {"name": data_dic["name"]},
                )
            else:
                self.cursor.execute(
                    """SELECT id FROM account WHERE name=:name""",
                    {"name": data_dic["name"]},
                )
            result = self.cursor.fetchone()[0]
            self._db_close()
        else:
            result = None
        self.logger.debug("DBStore.account_update() ended")
        return result

    def accountlist_get(self) -> Tuple[List[str], List[str]]:
        """accountlist_get"""
        self.logger.debug("DBStore.accountlist_get()")
        vlist = [
            "id",
            "name",
            "eab_kid",
            "contact",
            "created_at",
            "jwk",
            "alg",
            "order__id",
            "order__name",
            "order__status__id",
            "order__status__name",
            "order__notbefore",
            "order__notafter",
            "order__expires",
            "order__identifiers",
            "order__authorization__id",
            "order__authorization__name",
            "order__authorization__type",
            "order__authorization__value",
            "order__authorization__expires",
            "order__authorization__token",
            "order__authorization__created_at",
            "order__authorization__status__id",
            "order__authorization__status__name",
            "order__authorization__challenge__id",
            "order__authorization__challenge__name",
            "order__authorization__challenge__token",
            "order__authorization__challenge__expires",
            "order__authorization__challenge__type",
            "order__authorization__challenge__keyauthorization",
            "order__authorization__challenge__created_at",
            "order__authorization__challenge__status__id",
            "order__authorization__challenge__status__name",
        ]

        self._db_open()

        pre_statement = """SELECT account.*,
                           orders.id as order__id,
                           orders.name as order__name,
                           orders.status_id as order__status,
                           orders.notbefore as order__notbefore,
                           orders.notafter as order__notafter,
                           orders.expires as order__expires,
                           orders.identifiers as order__identifiers,
                           orders.created_at as order__created_at,
                           orders.status_id as order__status__id,
                           order_status.name as order__status__name,
                           authorization.id as order__authorization__id,
                           authorization.name as order__authorization__name,
                           authorization.type as order__authorization__type,
                           authorization.value as order__authorization__value,
                           authorization.expires as order__authorization__expires,
                           authorization.token as order__authorization__token,
                           authorization.created_at as order__authorization__created_at,
                           authorization.status_id as order__authorization__status__id,
                           auth_status.name as order__authorization__status__name,
                           challenge.id as order__authorization__challenge__id,
                           challenge.name as order__authorization__challenge__name,
                           challenge.token as order__authorization__challenge__token,
                           challenge.expires as order__authorization__challenge__expires,
                           challenge.type as order__authorization__challenge__type,
                           challenge.keyauthorization as order__authorization__challenge__keyauthorization,
                           challenge.created_at as order__authorization__challenge__created_at,
                           challenge.status_id as order__authorization__challenge__status__id,
                           chall_status.name as order__authorization__challenge__status__name
                           from account
                           JOIN orders on orders.account_id = account.id
                           JOIN authorization on authorization.order_id = orders.id
                           JOIN challenge on challenge.authorization_id = authorization.id
                           JOIN status as order_status on order_status.id = orders.status_id
                           JOIN status as auth_status on auth_status.id = authorization.status_id
                           JOIN status as chall_status on chall_status.id = challenge.status_id"""

        self.cursor.execute(pre_statement)
        rows = self.cursor.fetchall()

        # process results
        account_list = []
        for row in rows:
            lookup = dict_from_row(row)
            result = {}
            if lookup:
                for ele in vlist:
                    result[ele] = lookup[ele]

            account_list.append(result)

        self._db_close()
        return (vlist, account_list)

    def authorization_add(self, data_dic: Dict[str, str]) -> int:
        """add authorization to database"""
        self.logger.debug("DBStore.authorization_add(%s)", data_dic)
        self._db_open()
        self.cursor.execute(
            """INSERT INTO authorization(name, order_id, type, value) VALUES(:name, :order, :type, :value)""",
            data_dic,
        )
        rid = self.cursor.lastrowid
        self._db_close()
        self.logger.debug("DBStore.authorization_add() ended with: %s", rid)
        return rid

    def authorization_lookup(
        self, column: str, string: str, vlist: List[str] = ("type", "value")
    ) -> List[str]:
        """search account for a given id"""
        self.logger.debug(
            "DBStore.authorization_lookup(column:%s, pattern:%s)", column, string
        )

        try:
            lookup = self._authorization_search(column, string)
        except Exception as err:
            self.logger.error(
                "DBStore.authorization_lookup(column:%s, pattern:%s) failed with err: %s",
                column,
                string,
                err,
            )
            lookup = []

        authz_list = []
        for row in lookup:
            row_dic = dict_from_row(row)
            tmp_dic = {}
            for ele in vlist:
                tmp_dic[ele] = row_dic[ele]
            authz_list.append(tmp_dic)
        self.logger.debug("DBStore.authorization_lookup() ended")
        return authz_list

    def authorizations_expired_search(
        self,
        column: str,
        string: str,
        vlist: List[str] = (
            "id",
            "name",
            "expires",
            "value",
            "created_at",
            "token",
            "status__id",
            "status__name",
            "order__id",
            "order__name",
        ),
        operant="LIKE",
    ) -> List[str]:
        """search order table for a certain key/value pair"""
        self.logger.debug(
            "DBStore.authorizations_expired_search(column:%s, pattern:%s)",
            column,
            string,
        )
        if not self._identifier_check("authorization", column):
            self.logger.warning(COLUMN_NOT_IN_TABLE_MSG, column, "authorization")
            return []
        self._db_open()
        pre_statement = f"""SELECT
                                authorization.*,
                                status.name as status__name,
                                status.id as status__id,
                                orders.name as order__name,
                                orders.id as order__id
                                FROM authorization
                            LEFT JOIN status on status.id = authorization.status_id
                            LEFT JOIN orders on orders.id = authorization.order_id
                            WHERE status__name NOT LIKE 'expired' AND authorization.{column} {operant} ?"""

        self.cursor.execute(pre_statement, [string])
        rows = self.cursor.fetchall()

        authorization_list = []
        for row in rows:
            lookup = dict_from_row(row)
            result = {}
            if lookup:
                for ele in vlist:
                    result[ele] = lookup[ele]
            authorization_list.append(result)

        self._db_close()
        self.logger.debug("DBStore.authorizations_expired_search-() ended")
        return authorization_list

    def authorization_update(self, data_dic: Dict[str, str]) -> List[str]:
        """update existing authorization"""
        self.logger.debug("DBStore.authorization_update(%s)", data_dic)

        lookup = self._authorization_search("name", data_dic["name"])
        if lookup:
            lookup = dict_from_row(lookup[0])
            if "status" in data_dic:
                data_dic["status"] = dict_from_row(
                    self._status_search("name", data_dic["status"])
                )["id"]
            else:
                data_dic["status"] = lookup["status_id"]
            if "token" not in data_dic:
                data_dic["token"] = lookup["token"]
            if "expires" not in data_dic:
                data_dic["expires"] = lookup["expires"]

            self._db_open()
            self.cursor.execute(
                """UPDATE authorization SET status_id = :status, token = :token, expires = :expires WHERE name = :name""",
                data_dic,
            )
            self.cursor.execute(
                """SELECT id FROM authorization WHERE name=:name""",
                {"name": data_dic["name"]},
            )
            result = self.cursor.fetchone()[0]
            self._db_close()
        else:
            result = None
        self.logger.debug("DBStore.authorization_update() ended")
        return result

    def certificate_account_check(
        self, account_name: str, certificate: str
    ) -> List[str]:
        """check issuer against certificate"""
        self.logger.debug("DBStore.certificate_account_check(%s)", account_name)

        # search certificate table to get the order-id
        certificate_dic = self.certificate_lookup(
            "cert_raw", certificate, ["name", "order__name"]
        )

        result = None

        # search order table to get the account-name based on the order-id
        if "order__name" in certificate_dic:
            order_dic = self.order_lookup(
                "name", certificate_dic["order__name"], ["name", "account__name"]
            )
            if order_dic:
                if "account__name" in order_dic:
                    result = self._certificate_account_check(
                        account_name, certificate_dic, order_dic
                    )
                else:
                    self.logger.debug("account_name missing in order_dic")
            else:
                self.logger.debug("order_dic empty")

        self.logger.debug("DBStore.certificate_account_check() ended with: %s", result)
        return result

    def cahandler_add(self, data_dic: Dict[str, str]) -> int:
        """add cahandler values to database"""
        self.logger.debug("DBStore.cahandler_add(%s)", data_dic)
        if "value2" not in data_dic:
            data_dic["value2"] = ""

        # check if we alredy have an entry for the key
        exists = self.cahandler_lookup("name", data_dic["name"], ["id", "name"])
        self._db_open()
        if bool(exists):
            # update
            self.logger.debug(f'parameter exists: name id: {data_dic["name"]}')
            self.cursor.execute(
                """UPDATE CAHANDLER SET name = :name, value1 = :value1, 'value2' = :value2 WHERE name = :name""",
                data_dic,
            )
            rid = exists["id"]
        else:
            # insert
            self.cursor.execute(
                """INSERT INTO cahandler(name, value1, value2) VALUES(:name, :value1, :value2)""",
                data_dic,
            )
            rid = self.cursor.lastrowid

        self._db_close()
        self.logger.debug("DBStore.authorization_add() ended with: %s", rid)
        return rid

    def cahandler_lookup(
        self,
        column: str,
        string: str,
        vlist: List[str] = ["name", "value1", "value2", "created_at"],
    ) -> Dict[str, str]:
        """lookup ca handler"""
        self.logger.debug(
            "DBStore.cahandler_lookup(column:%s, pattern:%s)", column, string
        )

        try:
            lookup = dict_from_row(self._cahandler_search(column, string))
        except Exception:
            lookup = None

        result = {}
        if lookup:
            for ele in vlist:
                result[ele] = lookup[ele]
        else:
            result = {}

        self.logger.debug("DBStore.cahandler_lookup() ended")
        return result

    def cliaccount_add(self, data_dic: Dict[str, str]) -> int:
        """add cli user"""
        self.logger.debug("DBStore.cliuser_add(%s)", data_dic["name"])
        exists = self._cliaccount_search("name", data_dic["name"])

        rid = None
        self._db_open()
        if bool(exists):
            self.logger.debug("cliaccount exists: name id: %s", data_dic["name"])
            if "contact" not in data_dic:
                data_dic["contact"] = exists["contact"]
            if "jwk" not in data_dic:
                data_dic["jwk"] = exists["jwk"]
            self.cursor.execute(
                """UPDATE cliaccount SET name = :name, jwk = :jwk, 'contact' = :contact, 'reportadmin' = :reportadmin,  'cliadmin' = :cliadmin, 'certificateadmin' = :certificateadmin WHERE name = :name""",
                data_dic,
            )
            rid = exists["id"]
        else:
            self.cursor.execute(
                """INSERT INTO cliaccount(name, jwk, contact, reportadmin, cliadmin, certificateadmin) VALUES(:name, :jwk, :contact, :reportadmin, :cliadmin, :certificateadmin)""",
                data_dic,
            )
            rid = self.cursor.lastrowid
        self._db_close()
        self.logger.debug("DBStore.cliaccount_add() ended with: %s", rid)
        return rid

    def cliaccount_delete(self, data_dic: Dict[str, str]):
        """add cli user"""
        self.logger.debug("DBStore.cliaccount_delete(%s)", data_dic["name"])
        exists = self._cliaccount_search("name", data_dic["name"])
        if exists:
            self._db_open()
            self.cursor.execute("""DELETE FROM cliaccount WHERE name=:name""", data_dic)
            self._db_close()
        else:
            self.logger.error(
                "DBStore.cliaccount_delete() failed for kid: %s", data_dic["name"]
            )
        self.logger.debug("DBStore.cliaccount_delete() ended")

    def cliaccountlist_get(self) -> List[str]:
        """get cli accout list"""
        self.logger.debug("DBStore.cliaccountlist_get()")
        vlist = [
            "id",
            "name",
            "jwk",
            "contact",
            "created_at",
            "cliadmin",
            "reportadmin",
            "certificateadmin",
        ]

        self._db_open()
        pre_statement = """SELECT cliaccount.*
                            from cliaccount
                            WHERE cliaccount.name IS NOT NULL"""

        self.cursor.execute(pre_statement)
        rows = self.cursor.fetchall()
        # process results
        account_list = []
        for row in rows:
            lookup = dict_from_row(row)
            result = {}
            if lookup:
                for ele in vlist:
                    result[ele] = lookup[ele]
            account_list.append(result)

        self._db_close()
        return account_list

    def certificate_add(self, data_dic: Dict[str, str]) -> int:
        """add csr/certificate to database"""
        self.logger.debug("DBStore.certificate_add(%s)", data_dic["name"])
        # check if we alredy have an entry for the key
        exists = self._certificate_search("name", data_dic["name"])

        if bool(exists):
            if "poll_identifier" not in data_dic:
                data_dic["poll_identifier"] = exists["poll_identifier"]
            if "renewal_info" not in data_dic:
                data_dic["renewal_info"] = exists["renewal_info"]
            if "header_info" not in data_dic:
                data_dic["header_info"] = exists["header_info"]
            if "aki" not in data_dic:
                data_dic["aki"] = exists["aki"]
            if "serial" not in data_dic:
                data_dic["serial"] = exists["serial"]
            rid = self._certificate_update(data_dic, exists)
        else:
            rid = self._certificate_insert(data_dic)

        self.logger.debug("DBStore.certificate_add() ended with: %s", rid)
        return rid

    def certificate_delete(self, mkey: str, string: str) -> Tuple[List[str], List[str]]:
        """delete certificate from table"""
        self.logger.debug("DBStore.certificate_delete(%s:%s)", mkey, string)
        self._db_open()
        pre_statement = f"""DELETE from certificate WHERE {mkey} = ?"""
        self.cursor.execute(pre_statement, [string])
        self._db_close()

    def certificatelist_get(self) -> Tuple[List[str], List[str]]:
        """certificatelist_get"""
        self.logger.debug("DBStore.certificatelist_get()")
        vlist = [
            "id",
            "name",
            "cert_raw",
            "csr",
            "poll_identifier",
            "created_at",
            "issue_uts",
            "expire_uts",
            "order__id",
            "order__name",
            "order__status__name",
            "order__notbefore",
            "order__notafter",
            "order__expires",
            "order__identifiers",
            "order__account__name",
            "order__account__contact",
            "order__account__created_at",
            "order__account__jwk",
            "order__account__alg",
            "order__account__eab_kid",
        ]

        self._db_open()
        pre_statement = """SELECT certificate.*,
                            orders.id as order__id,
                            orders.name as order__name,
                            orders.status_id as order__status__name,
                            orders.notbefore as order__notbefore,
                            orders.notafter as order__notafter,
                            orders.expires as order__expires,
                            orders.identifiers as order__identifiers,
                            account.name as order__account__name,
                            account.contact as order__account__contact,
                            account.created_at as order__account__created_at,
                            account.jwk as order__account__jwk,
                            account.alg as order__account__alg,
                            account.eab_kid as order__account__eab_kid
                            from certificate
                            INNER JOIN orders on orders.id = certificate.order_id
                            INNER JOIN account on account.id = orders.account_id
                            WHERE certificate.cert_raw IS NOT NULL"""

        self.cursor.execute(pre_statement)
        rows = self.cursor.fetchall()
        # process results
        cert_list = []
        for row in rows:
            lookup = dict_from_row(row)
            result = {}
            if lookup:
                for ele in vlist:
                    result[ele] = lookup[ele]
            cert_list.append(result)

        self._db_close()
        return (vlist, cert_list)

    def certificate_lookup(
        self,
        column: str,
        string: str,
        vlist: List[str] = ("name", "csr", "cert", "order__name"),
    ) -> Dict[str, str]:
        """search certificate based on "something" """
        self.logger.debug("DBstore.certificate_lookup(%s:%s)", column, string)

        try:
            lookup = dict_from_row(self._certificate_search(column, string))
        except Exception:
            lookup = None

        result = {}
        if lookup:
            for ele in vlist:
                result[ele] = lookup[ele]
                if ele == "order__name":
                    result["order"] = lookup[ele]
        else:
            result = {}

        self.logger.debug("DBStore.certificate_lookup() ended with: %s", result)
        return result

    def certificates_search(
        self,
        column: str,
        string: str,
        vlist: List[str] = ("name", "csr", "cert", "order__name"),
        operant="LIKE",
    ) -> List[str]:
        """search certificate table for a certain key/value pair"""
        self.logger.debug(
            "DBStore.certificates_search(column:%s, pattern:%s)", column, string
        )
        if not self._identifier_check("certificate", column):
            self.logger.warning(COLUMN_NOT_IN_TABLE_MSG, column, "certificate")
            return []

        self._db_open()
        if column == "order__status_id":
            column = "orders.status_id"
            self.logger.debug("modified column to %s", column)

        pre_statement = f"""SELECT certificate.*,
                            orders.id as order__id,
                            orders.name as order__name,
                            orders.status_id as order__status_id,
                            account.name as order__account__name
                            from certificate
                            INNER JOIN orders on orders.id = certificate.order_id
                            INNER JOIN account on account.id = orders.account_id
                            WHERE {column} {operant} ?"""
        self.cursor.execute(pre_statement, [string])
        rows = self.cursor.fetchall()
        cert_list = []
        for row in rows:
            lookup = dict_from_row(row)
            result = {}
            if lookup:
                for ele in vlist:
                    result[ele] = lookup[ele]
                    if ele == "order__name":
                        result["order"] = lookup[ele]
            cert_list.append(result)

        self._db_close()
        self.logger.debug("DBStore.certificates_search() ended")
        return cert_list

    def challenges_search(
        self,
        column: str,
        string: str,
        vlist: List[str] = ("name", "type", "status__name", "token"),
    ) -> List[str]:
        """search challenge table for a certain key/value pair"""
        self.logger.debug(
            "DBStore._challenge_search(column:%s, pattern:%s)", column, string
        )
        if not self._identifier_check("challenge", column):
            self.logger.warning(COLUMN_NOT_IN_TABLE_MSG, column, "challenge")
            return []

        self._db_open()
        pre_statement = f"""
            SELECT
                challenge.*,
                status.id as status__id,
                status.name as status__name,
                authorization.id as authorization__id,
                authorization.name as authorization__name,
                authorization.type as authorization__type,
                authorization.value as authorization__value,
                authorization.token as authorization__token,
                orders.name as authorization__order__name,
                account.name as authorization__order__account__name
            from challenge
            INNER JOIN status on status.id = challenge.status_id
            INNER JOIN authorization on authorization.id = challenge.authorization_id
            INNER JOIN orders on orders.id = authorization.order_id
            INNER JOIN account on account.id = orders.account_id
            WHERE {column} LIKE ?"""
        self.cursor.execute(pre_statement, [string])
        rows = self.cursor.fetchall()
        challenge_list = []
        for row in rows:
            lookup = dict_from_row(row)
            result = {}
            if lookup:
                for ele in vlist:
                    result[ele] = lookup[ele]
                    if ele == "status__name":
                        result["status"] = lookup[ele]
            challenge_list.append(result)
        self._db_close()
        self.logger.debug("DBStore._challenge_search() ended")
        return challenge_list

    def challenge_add(self, value: str, mtype: str, data_dic: Dict[str, str]) -> int:
        """add challenge to database"""
        self.logger.debug("DBStore.challenge_add(%s:%s)", value, mtype)
        authorization = self.authorization_lookup(
            "name", data_dic["authorization"], ["id"]
        )

        if "status" not in data_dic:
            data_dic["status"] = 2
        if authorization:
            data_dic["authorization"] = authorization[0]["id"]
            self._db_open()
            self.cursor.execute(
                """INSERT INTO challenge(name, token, authorization_id, expires, type, status_id) VALUES(:name, :token, :authorization, :expires, :type, :status)""",
                data_dic,
            )
            rid = self.cursor.lastrowid
            self._db_close()
        else:
            rid = None
        self.logger.debug("DBStore.challenge_add() ended")
        return rid

    def challenge_lookup(
        self,
        column: str,
        string: str,
        vlist: List[str] = ("type", "token", "status__name"),
    ) -> Dict[str, str]:
        """search account for a given id"""
        self.logger.debug("DBStore.challenge_lookup(%s:%s)", column, string)

        try:
            lookup = dict_from_row(self._challenge_search(column, string))
        except Exception:
            lookup = None

        result = {}
        if lookup:
            for ele in vlist:
                if ele == "status__name":
                    result["status"] = lookup["status__name"]
                elif ele == "authorization__name":
                    result["authorization"] = lookup["authorization__name"]
                else:
                    result[ele] = lookup[ele]

        self.logger.debug("DBStore.challenge_lookup() ended with:%s", result)
        return result

    def challenge_update(self, data_dic: Dict[str, str]):
        """update challenge"""
        self.logger.debug("DBStore.challenge_update(%s)", data_dic)
        lookup = self._challenge_search("name", data_dic["name"])
        lookup = dict_from_row(lookup)

        if "status" in data_dic:
            data_dic["status"] = dict_from_row(
                self._status_search("name", data_dic["status"])
            )["id"]
        else:
            data_dic["status"] = lookup["status__id"]

        if "keyauthorization" not in data_dic:
            data_dic["keyauthorization"] = lookup["keyauthorization"]

        if "validated" not in data_dic:
            data_dic["validated"] = lookup["validated"]

        self._db_open()
        self.cursor.execute(
            """UPDATE challenge SET status_id = :status, keyauthorization = :keyauthorization, validated = :validated WHERE name = :name""",
            data_dic,
        )
        self._db_close()
        self.logger.debug("DBStore.challenge_update() ended")

    def cli_jwk_load(self, aname: str) -> Dict[str, str]:
        """looad cliaccount information and build jwk key dictionary"""
        self.logger.debug("DBStore.cli_jwk_load(%s)", aname)
        account_list = self._cliaccount_search("name", aname)
        jwk_dict = {}
        if account_list:
            jwk_dict = json.loads(account_list[2])
        self.logger.debug("DBStore.jwk_load() ended with: %s", jwk_dict)
        return jwk_dict

    def cli_permissions_get(self, aname: str) -> Dict[str, str]:
        """looad cliaccount information and build jwk key dictionary"""
        self.logger.debug("DBStore.cli_jwk_load(%s)", aname)
        account_list = self._cliaccount_search("name", aname)
        account_dic = {}
        if account_list:
            account_dic = {
                "cliadmin": account_list["cliadmin"],
                "reportadmin": account_list["reportadmin"],
                "certificateadmin": account_list["certificateadmin"],
            }

        return account_dic

    def db_update(self):
        """update database"""
        self.logger.debug("DBStore.db_update()")
        self._db_open()

        # update certificate table
        self._db_update_certificate()

        # update status table
        self._db_update_status()

        # update challenge table
        self._db_update_challenge()

        # update account table
        self._db_update_account()

        # update order table
        self._db_update_orders()

        # update authorization table
        self._db_update_authorization()

        # create housekeeping table
        self._db_update_housekeeping()

        # create ca_handler table
        self._db_update_cahandler()

        # create cliaccount table
        self._db_update_cliaccount()

        # version update
        self.logger.info(f"update dbversion to {__dbversion__}")
        self.cursor.execute(
            f"""INSERT OR IGNORE INTO housekeeping (name, value) VALUES ("dbversion", "{__dbversion__}")"""
        )
        self.cursor.execute(
            f'''UPDATE housekeeping SET value = "{__dbversion__}" WHERE name="dbversion"'''
        )

        self._db_close()
        self.logger.debug("DBStore.db_update() ended")

    def dbversion_get(self) -> Tuple[List[str], str]:
        """get db version from housekeeping table"""
        self.logger.debug("DBStore.dbversion_get()")
        self._db_open()
        pre_statement = "SELECT value from housekeeping WHERE housekeeping.name LIKE ?"
        self.cursor.execute(pre_statement, ["dbversion"])
        query = list(self.cursor.fetchone())
        if query:
            result = query[0]
        else:
            self.logger.error("DBStore.dbversion_get() lookup failed")
            result = None
        self._db_close()
        self.logger.debug("DBStore.dbversion_get() ended with %s", result)
        return (result, "tools/db_update.py")

    def hkparameter_add(self, data_dic: Dict[str, str]) -> Tuple[str, bool]:
        """add housekeeping paramter to database"""
        # we need this for compability with django
        created = False
        # check if we alredy have an entry for the key
        exists = self.hkparameter_get(data_dic["name"])
        self._db_open()
        if bool(exists):
            # update
            self.logger.debug(f'parameter exists: {data_dic["name"]}')
            self.cursor.execute(
                """UPDATE HOUSEKEEPING SET name = :name, value = :value WHERE name = :name""",
                data_dic,
            )
        else:
            # insert
            self.cursor.execute(
                """INSERT INTO HOUSEKEEPING(name, value) VALUES(:name, :value)""",
                data_dic,
            )
            created = True

        self._db_close()
        self.logger.debug("DBStore.account_add() ended")
        return (data_dic["name"], created)

    def hkparameter_get(self, parameter: str) -> List[str]:
        """get parameter from housekeeping table"""
        self.logger.debug("DBStore.hkparameter_get()")
        self._db_open()
        pre_statement = "SELECT value from housekeeping WHERE housekeeping.name LIKE ?"
        self.cursor.execute(pre_statement, [parameter])
        try:
            query = list(self.cursor.fetchone())
        except Exception:
            query = None

        if query:
            result = query[0]
        else:
            result = None
        self._db_close()
        self.logger.debug("DBStore.hkparameter_get() ended with %s", result)
        return result

    def jwk_load(self, aname: str) -> Dict[str, str]:
        """looad account informatino and build jwk key dictionary"""
        self.logger.debug("DBStore.jwk_load(%s)", aname)
        account_list = self._account_search("name", aname)
        jwk_dict = {}
        if account_list:
            jwk_dict = json.loads(account_list[3])
            jwk_dict["alg"] = account_list[2]
        self.logger.debug("DBStore.jwk_load() ended with: %s", jwk_dict)
        return jwk_dict

    def nonce_add(self, nonce: str) -> int:
        """check if nonce is in datbase
        in: nonce
        return: rowid"""
        self.logger.debug("DBStore.nonce_add(%s)", nonce)
        self._db_open()
        self.cursor.execute(
            """INSERT INTO nonce(nonce) VALUES(:nonce)""", {"nonce": nonce}
        )
        rid = self.cursor.lastrowid
        self._db_close()
        self.logger.debug("DBStore.nonce_add() ended")
        return rid

    def nonce_check(self, nonce: str) -> bool:
        """ceck if nonce is in datbase
        in: nonce
        return: true in case nonce exit, otherwise false"""
        self.logger.debug("DBStore.nonce_check(%s)", nonce)
        self._db_open()
        self.cursor.execute(
            """SELECT nonce FROM nonce WHERE nonce=:nonce""", {"nonce": nonce}
        )
        result = bool(self.cursor.fetchone())
        self._db_close()
        self.logger.debug("DBStore.nonce_check() ended")
        return result

    def nonce_delete(self, nonce: str):
        """delete nonce from datbase
        in: nonce"""
        self.logger.debug("DBStore.nonce_delete(%s)", nonce)
        self._db_open()
        self.cursor.execute(
            """DELETE FROM nonce WHERE nonce=:nonce""", {"nonce": nonce}
        )
        self._db_close()
        self.logger.debug("DBStore.nonce_delete() ended")

    def order_add(self, data_dic: Dict[str, str]) -> int:
        """add order to database"""
        self.logger.debug("DBStore.order_add(%s)", data_dic)
        if "notbefore" not in data_dic:
            data_dic["notbefore"] = ""

        if "notafter" not in data_dic:
            data_dic["notafter"] = ""

        account = self.account_lookup("name", data_dic["account"])
        if account:
            data_dic["account"] = account["id"]
            self._db_open()
            self.cursor.execute(
                """INSERT INTO orders(name, identifiers, account_id, status_id, expires, notbefore, notafter) VALUES(:name, :identifiers, :account, :status, :expires, :notbefore, :notafter )""",
                data_dic,
            )
            rid = self.cursor.lastrowid
            self._db_close()
        else:
            rid = None
        self.logger.debug("DBStore.order_add() ended")
        return rid

    def order_lookup(
        self,
        column: str,
        string: str,
        vlist: List[str] = (
            "notbefore",
            "notafter",
            "identifiers",
            "expires",
            "status__name",
        ),
    ) -> Dict[str, str]:
        """search orders for a given ordername"""
        self.logger.debug("order_lookup(%s:%s)", column, string)

        try:
            lookup = dict_from_row(self._order_search(column, string))
        except Exception:
            lookup = None

        result = {}
        if lookup:
            # small hack (not sure db returnsblank and not 0)
            if lookup["notafter"] == "":
                lookup["notafter"] = 0
            if lookup["notbefore"] == "":
                lookup["notbefore"] = 0
            for ele in vlist:
                if ele == "status__name":
                    result["status"] = lookup["status__name"]
                else:
                    result[ele] = lookup[ele]

        self.logger.debug("DBStore.order_lookup() ended with: %s", result)
        return result

    def order_update(self, data_dic: Dict[str, str]):
        """update order"""
        self.logger.debug("order_update(%s)", data_dic)
        if "status" in data_dic:
            data_dic["status"] = dict_from_row(
                self._status_search("name", data_dic["status"])
            )["id"]
        self._db_open()
        self.cursor.execute(
            """UPDATE orders SET status_id = :status WHERE name = :name""", data_dic
        )
        self._db_close()
        self.logger.debug("DBStore.order_update() ended")

    def orders_invalid_search(
        self,
        column: str,
        string: str,
        vlist: List[str] = (
            "id",
            "name",
            "expires",
            "identifiers",
            "created_at",
            "status__id",
            "status__name",
            "account__id",
            "account__name",
            "account__contact",
        ),
        operant="LIKE",
    ) -> List[str]:
        """search order table for a certain key/value pair"""
        self.logger.debug(
            "DBStore.orders_invalid_search(column:%s, pattern:%s)", column, string
        )
        if not self._identifier_check("orders", column):
            self.logger.warning(COLUMN_NOT_IN_TABLE_MSG, column, "orders")
            return []

        self._db_open()
        pre_statement = f"""SELECT
                                orders.*,
                                status.name as status__name,
                                status.id as status__id,
                                account.name as account__name,
                                account.contact as account__contact,
                                account.id as account__id
                                FROM orders
                            LEFT JOIN status on status.id = orders.status_id
                            LEFT JOIN account on account.id = orders.account_id
                            WHERE orders.status_id > 1 AND orders.{column} {operant} ?"""
        self.cursor.execute(pre_statement, [string])
        rows = self.cursor.fetchall()
        order_list = []
        for row in rows:
            lookup = dict_from_row(row)
            result = {}
            if lookup:
                for ele in vlist:
                    result[ele] = lookup[ele]
            order_list.append(result)

        self._db_close()
        self.logger.debug("DBStore.orders_invalid_search() ended")
        return order_list
