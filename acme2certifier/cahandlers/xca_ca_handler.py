# pylint: disable=e0401, c0302
# -*- coding: utf-8 -*-
"""handler for xca ca handler"""

import hashlib
import logging
import os
import re
import sqlite3
import uuid
import json
import datetime
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import (
    BasicConstraints,
    ExtendedKeyUsage,
    SubjectKeyIdentifier,
    AuthorityKeyIdentifier,
    KeyUsage,
    SubjectAlternativeName,
)
from cryptography.x509.oid import ExtendedKeyUsageOID

# we cannot remove this import as it is used in the code as CA’s iss_hash has to line up with hashes XCA already stored when the CA was imported
from OpenSSL import crypto as pyossslcrypto
from acme2certifier.acme_srv.helper import (
    b64_decode,
    b64_encode,
    b64_url_recode,
    build_pem_file,
    cert_serial_get,
    config_eab_profile_load,
    config_enroll_config_log_load,
    config_headerinfo_load,
    config_option_load,
    config_profile_load,
    convert_byte_to_string,
    convert_string_to_byte,
    csr_cn_get,
    csr_san_get,
    eab_profile_header_info_check,
    eab_profile_revocation_check,
    enrollment_config_log,
    error_dic_get,
    load_config,
    uts_now,
    uts_to_date_utc,
)
from acme2certifier.acme_srv.helpers.global_variables import CONFIGURATION_ERROR_DETAIL

# Define constants
DEFAULT_DATE_FORMAT = "%Y%m%d%H%M%SZ"
COLUMN_NOT_IN_TABLE_MSG = "column: %s not in %s table"
XDB_ENGINE_MAP = {
    "sqlite": "sqlite",
    "mysql": "mysql",
    "mariadb": "mysql",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "pgsql": "postgresql",
}
XCA_RELATIONS = (
    "settings",
    "items",
    "public_keys",
    "private_keys",
    "tokens",
    "token_mechanism",
    "x509super",
    "requests",
    "certs",
    "authority",
    "crls",
    "revocations",
    "templates",
    "takeys",
    "view_public_keys",
    "view_certs",
    "view_requests",
    "view_crls",
    "view_templates",
    "view_private",
)
_XCA_PREFIX_RE = re.compile(
    r"\b("
    + "|".join(
        re.escape(name)
        for name in list(XCA_RELATIONS) + [f"i_{name}" for name in XCA_RELATIONS]
    )
    + r")\b",
    re.IGNORECASE,
)
_NAMED_PARAM_RE = re.compile(r":([A-Za-z_][A-Za-z0-9_]*)")


def dict_from_row(row: Optional[Any]) -> Dict[str, Any]:
    """small helper to convert the output of a "select" command into a dictionary"""
    if row is None:
        return {}
    if isinstance(row, dict):
        return {str(key).lower(): value for key, value in row.items()}
    return {str(key).lower(): value for key, value in zip(row.keys(), tuple(row))}


class _XcaCursor:
    """Cursor proxy that applies table-prefix and placeholder conversion."""

    def __init__(self, cursor: Any, convert_sql) -> None:
        self._cursor = cursor
        self._convert_sql = convert_sql

    def execute(self, sql: str, params: Any = None):
        sql, params = self._convert_sql(sql, params)
        if params is None:
            return self._cursor.execute(sql)
        return self._cursor.execute(sql, params)

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    @property
    def lastrowid(self):
        return self._cursor.lastrowid

    @property
    def rowcount(self):
        return getattr(self._cursor, "rowcount", 0)

    @property
    def description(self):
        return self._cursor.description


class XcaDb:
    """SQLite / MySQL / PostgreSQL adapter for the XCA schema."""

    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        self.logger = logger
        self.engine = "sqlite"
        self.xdb_file: Optional[str] = None
        self.host: Optional[str] = None
        self.port: Optional[int] = None
        self.name: Optional[str] = None
        self.user: Optional[str] = None
        self.password: Optional[str] = None
        self.table_prefix = ""
        self.ssl_ca: Optional[str] = None
        self.ssl_mode: Optional[str] = None
        self.connection = None

    def configure(
        self,
        *,
        engine: str = "sqlite",
        xdb_file: Optional[str] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        name: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        table_prefix: Optional[str] = None,
        ssl_ca: Optional[str] = None,
        ssl_mode: Optional[str] = None,
    ) -> None:
        self.engine = engine or "sqlite"
        self.xdb_file = xdb_file
        self.host = host
        self.port = port
        self.name = name
        self.user = user
        self.password = password
        self.table_prefix = table_prefix or ""
        self.ssl_ca = ssl_ca
        self.ssl_mode = ssl_mode

    def is_remote(self) -> bool:
        return self.engine in ("mysql", "postgresql")

    def rewrite_prefix(self, sql: str) -> str:
        """Prepend XCA table prefix like XSqlQuery::rewriteQuery."""
        if not self.table_prefix:
            return sql
        return _XCA_PREFIX_RE.sub(
            lambda match: f"{self.table_prefix}{match.group(1).lower()}", sql
        )

    def convert_sql(self, sql: str, params: Any = None) -> Tuple[str, Any]:
        sql = self.rewrite_prefix(sql)
        if self.engine == "sqlite":
            return sql, params
        if isinstance(params, dict):
            return _NAMED_PARAM_RE.sub(r"%(\1)s", sql), params
        return sql.replace("?", "%s"), params

    def connect(self) -> Tuple[Any, _XcaCursor]:
        """Connect to database"""
        self.logger.debug("XcaDb.connect()")
        if self.engine == "sqlite":
            connection = sqlite3.connect(self.xdb_file)
            connection.row_factory = sqlite3.Row
            cursor = connection.cursor()
        elif self.engine == "mysql":
            connection, cursor = self._connect_mysql()
        elif self.engine == "postgresql":
            connection, cursor = self._connect_postgresql()
        else:
            raise ValueError(f"unsupported xdb_engine {self.engine}")
        self.connection = connection
        self.logger.debug("XcaDb.connect() ended")
        return connection, _XcaCursor(cursor, self.convert_sql)

    def _connect_mysql(self) -> Tuple[Any, Any]:
        """Connect to MySQL/MariaDB database"""
        self.logger.debug("XcaDb._connect_mysql()")
        try:
            import pymysql
            import pymysql.cursors
        except ImportError as err:
            raise ImportError(
                "PyMySQL is required for xdb_engine=mysql/mariadb"
            ) from err
        kwargs: Dict[str, Any] = {
            "host": self.host,
            "user": self.user,
            "password": self.password,
            "database": self.name,
            "cursorclass": pymysql.cursors.DictCursor,
        }
        if self.port:
            kwargs["port"] = self.port
        if self.ssl_ca or self.ssl_mode:
            ssl_dic: Dict[str, Any] = {}
            if self.ssl_ca:
                ssl_dic["ca"] = self.ssl_ca
            if self.ssl_mode == "verify-full":
                ssl_dic["check_hostname"] = True
            kwargs["ssl"] = ssl_dic
        connection = pymysql.connect(**kwargs)
        cursor = connection.cursor()
        cursor.execute("SET SESSION sql_mode = 'ANSI'")
        self.logger.debug("XcaDb._connect_mysql() ended")
        return connection, cursor

    def _connect_postgresql(self) -> Tuple[Any, Any]:
        """Connect to PostgreSQL database"""
        self.logger.debug("XcaDb._connect_postgresql()")
        try:
            import psycopg2
            import psycopg2.extras
        except ImportError as err:
            raise ImportError("psycopg2 is required for xdb_engine=postgresql") from err
        kwargs: Dict[str, Any] = {
            "host": self.host,
            "user": self.user,
            "password": self.password,
            "dbname": self.name,
            "cursor_factory": psycopg2.extras.RealDictCursor,
        }
        if self.port:
            kwargs["port"] = self.port
        if self.ssl_mode:
            kwargs["sslmode"] = self.ssl_mode
        if self.ssl_ca:
            kwargs["sslrootcert"] = self.ssl_ca
        connection = psycopg2.connect(**kwargs)
        self.logger.debug("XcaDb._connect_postgresql() ended")
        return connection, connection.cursor()

    def catalog_sql(self) -> str:
        if self.engine == "mysql":
            self.logger.debug("XcaDb.catalog_sql() mysql")
            return (
                "SELECT table_name AS name FROM information_schema.tables "
                "WHERE table_schema = DATABASE()"
            )
        if self.engine == "postgresql":
            self.logger.debug("XcaDb.catalog_sql() postgresql")
            return (
                "SELECT table_name AS name FROM information_schema.tables "
                "WHERE table_schema = current_schema()"
            )
        self.logger.debug("XcaDb.catalog_sql() sqlite")
        return "SELECT name FROM sqlite_master WHERE type = 'table' or type = 'view'"

    def physical_name(self, table: str) -> str:
        return f"{self.table_prefix}{table}"


class CAhandler:
    """CA  handler"""

    def __init__(
        self, debug: bool = False, logger: Optional[logging.Logger] = None
    ) -> None:
        self.debug = debug
        self.logger = logger
        self.xdb_file: Optional[str] = None
        self.xdb_permission = "660"
        self.passphrase: Optional[str] = None
        self.issuing_ca_name: Optional[str] = None
        self.issuing_ca_key: Optional[str] = None
        self.cert_validity_days = 365
        self.ca_cert_chain_list: List[str] = []
        self.template_name: Optional[str] = None
        self.header_info_field = None
        self.eab_handler = None
        self.eab_profiling = False
        self.enrollment_config_log = False
        self.enrollment_config_log_skip_list: List[str] = []
        self.profiles: Dict[str, Any] = {}
        self.profile_mapping_field = "template_name"
        self.xdb_engine = "sqlite"
        self.xdb_host: Optional[str] = None
        self.xdb_port: Optional[int] = None
        self.xdb_name: Optional[str] = None
        self.xdb_user: Optional[str] = None
        self.xdb_password: Optional[str] = None
        self.xdb_table_prefix = ""
        self.xdb_ssl_ca: Optional[str] = None
        self.xdb_ssl_mode: Optional[str] = None
        self.dbs = None
        self.cursor = None
        self.xca_db = XcaDb(logger)
        self._db_refcount = 0

    def __enter__(self):
        """Makes ACMEHandler a Context Manager"""
        if not self._db_configured():
            self._config_load()
        return self

    def __exit__(self, *args):
        """close the connection at the end of the context"""
        while self._db_refcount > 0:
            self._db_close()
        self._db_disconnect()

    def _asn1_stream_parse(self, asn1_stream: str = None) -> Dict[str, str]:
        """parse asn_string"""

        self.logger.debug("CAhandler._asn1_stream_parse()")
        oid_dic = {
            "2.5.4.3": "commonName",
            "2.5.4.4": "surname",
            "2.5.4.5": "serialNumber",
            "2.5.4.6": "countryName",
            "2.5.4.7": "localityName",
            "2.5.4.8": "stateOrProvinceName",
            "2.5.4.9": "streetAddress",
            "2.5.4.10": "organizationName",
            "2.5.4.11": "organizationalUnitName",
            "2.5.4.12": "title",
            "2.5.4.13": "description",
            "2.5.4.42": "givenName",
        }

        dn_dic = {}
        if asn1_stream:

            # cut first 8 bytes which are bogus
            # asn1_stream = asn1_stream[8:]

            # split stream
            stream_list = asn1_stream.split(b"\x06\x03\x55")
            # we have to remove the first element from list as it contains junk
            stream_list.pop(0)

            for ele in stream_list:
                oid = f"2.5.{ele[0]}.{ele[1]}"
                if oid in oid_dic:
                    value_len = ele[3]
                    value = ele[4 : 4 + value_len]
                    dn_dic[oid_dic[oid]] = value.decode("utf-8")

            self.logger.debug("CAhandler._asn1_stream_parse() ended: %s", bool(dn_dic))
        return dn_dic

    def _ca_cert_load(self) -> Tuple[object, int]:
        """load ca key from database"""
        self.logger.debug("CAhandler._ca_cert_load({%s)", self.issuing_ca_name)

        # query database for key
        self._db_open()
        pre_statement = """SELECT * from view_certs WHERE name LIKE ?"""
        self.cursor.execute(pre_statement, [self.issuing_ca_name])
        row = self.cursor.fetchone()
        try:
            db_result = dict_from_row(row)
        except Exception as err:
            self.logger.error("Certificate lookup in database failed: %s", err)
            db_result = {}
        self._db_close()

        ca_cert = None
        ca_id = None

        if "cert" in db_result:
            try:
                ca_cert = x509.load_der_x509_certificate(
                    b64_decode(self.logger, db_result["cert"]),
                    backend=default_backend(),
                )
                ca_id = db_result["id"]
            except Exception as err_:
                self.logger.error(
                    "Failed to load CA certificate from database: %s", err_
                )

        return (ca_cert, ca_id)

    def _ca_key_load(self) -> object:
        """load ca key from database"""
        self.logger.debug("CAhandler._ca_key_load(%s)", self.issuing_ca_key)

        # query database for key
        self._db_open()
        pre_statement = """SELECT * from view_private WHERE name LIKE ?"""
        self.cursor.execute(pre_statement, [self.issuing_ca_key])
        row = self.cursor.fetchone()
        try:
            db_result = dict_from_row(row)
        except Exception as err:
            self.logger.error("Failed to load CA private key from database: %s", err)
            db_result = {}
        self._db_close()

        ca_key = None
        if db_result and "private" in db_result:
            try:
                private_key = f'-----BEGIN ENCRYPTED PRIVATE KEY-----\n{db_result["private"]}\n-----END ENCRYPTED PRIVATE KEY-----'
                ca_key = serialization.load_pem_private_key(
                    convert_string_to_byte(private_key),
                    password=convert_string_to_byte(self.passphrase),
                    backend=default_backend(),
                )
            except Exception as err_:
                self.logger.error(
                    "Failed to load CA private key from database: %s", err_
                )
        else:
            self.logger.error("Failed to load CA private key: %s", db_result)

        self.logger.debug("CAhandler._ca_key_load() ended")
        return ca_key

    def _ca_load(self) -> Tuple[object, object, int]:
        """load ca key and cert"""
        self.logger.debug("CAhandler._ca_load()")
        ca_key = self._ca_key_load()
        ca_cert, ca_id = self._ca_cert_load()

        self.logger.debug("CAhandler._ca_load() ended")
        return (ca_key, ca_cert, ca_id)

    def _cdp_list_generate(self, cdp_string: str = None) -> List[str]:
        """generate cdp list"""
        self.logger.debug("CAhandler._cdp_list_generate()")

        cdp_list = []
        if cdp_string:
            for ele in cdp_string.split(","):
                cdp_list.append(
                    x509.DistributionPoint(
                        [x509.UniformResourceIdentifier(ele.strip())],
                        crl_issuer=None,
                        reasons=None,
                        relative_name=None,
                    )
                )

        self.logger.debug("CAhandler._cdp_list_generate() ended")
        return cdp_list

    def _cert_insert(self, cert_dic: Dict[str, str] = None) -> int:
        """insert new entry to request table"""
        self.logger.debug("CAhandler._cert_insert()")

        row_id = None
        if cert_dic:
            if all(
                key in cert_dic
                for key in (
                    "item",
                    "serial",
                    "issuer",
                    "ca",
                    "cert",
                    "iss_hash",
                    "hash",
                )
            ):
                # pylint: disable=R0916
                if (
                    isinstance(cert_dic["item"], int)
                    and isinstance(cert_dic["issuer"], int)
                    and isinstance(cert_dic["ca"], int)
                    and isinstance(cert_dic["iss_hash"], int)
                    and isinstance(cert_dic["hash"], int)
                ):
                    self._db_open()
                    self.cursor.execute(
                        """INSERT INTO certs(item, serial, issuer, ca, cert, hash, iss_hash) VALUES(:item, :serial, :issuer, :ca, :cert, :hash, :iss_hash)""",
                        cert_dic,
                    )
                    row_id = self._inserted_row_id()
                    self._db_close()
                else:
                    self.logger.error(
                        "Certificate insert aborted due to wrong datatypes: %s",
                        cert_dic,
                    )
            else:
                self.logger.error(
                    "Certificate insert aborted due to incomplete dataset: %s", cert_dic
                )
        else:
            self.logger.error("Certificate insert aborted: dataset is empty")

        self.logger.debug("CAhandler._cert_insert() ended with row_id: %s", row_id)
        return row_id

    def _cert_search(self, column: str, value: str) -> Dict[str, str]:
        """load ca key from database"""
        self.logger.debug("CAhandler._cert_search({%s:%s)", column, value)

        if not self._identifier_check("items", column):
            self.logger.warning(COLUMN_NOT_IN_TABLE_MSG, column, "items")
            return {}

        # query database for key
        self._db_open()
        pre_statement = f"""SELECT * from items WHERE type = 3 and {column} LIKE ?"""
        self.cursor.execute(pre_statement, [value])

        cert_result = {}
        row = self.cursor.fetchone()
        try:
            item_result = dict_from_row(row)
        except Exception as err:
            self.logger.error("Certificate item search in database failed: %s", err)
            item_result = {}

        if item_result:
            item_id = item_result["id"]
            pre_statement = """SELECT * from certs WHERE item LIKE ?"""
            self.cursor.execute(pre_statement, [item_id])
            cert_row = self.cursor.fetchone()
            try:
                cert_result = dict_from_row(cert_row)
            except Exception as err:
                self.logger.error(
                    "Certificate search in database failed for item %s: %s",
                    item_id,
                    err,
                )

        self._db_close()
        self.logger.debug("CAhandler._cert_search() ended")
        return cert_result

    def _cert_subject_generate(
        self, req: object, request_name: str, dn_dic: Dict[str, str] = None
    ) -> str:
        """set subject"""
        self.logger.debug("CAhandler._cert_subject_generate()")

        if not bool(req.subject):
            self.logger.info("Rewrite CN to %s", request_name)
            subject = x509.Name(
                [x509.NameAttribute(x509.NameOID.COMMON_NAME, request_name)]
            )
        else:
            subject = req.subject

        if dn_dic:
            # modify subject according to template
            subject = self._subject_modify(subject, dn_dic)

        self.logger.debug("CAhandler._cert_subject_generate() ended")
        return subject

    def _cert_sign(
        self, csr: str, request_name: str, ca_key: object, ca_cert: object, ca_id: int
    ) -> Tuple[str, str]:  # pylint: disable=R0913
        self.logger.debug("Certificate._cert_sign()")

        if self.enrollment_config_log:
            self.enrollment_config_log_skip_list.extend(
                ["dbs", "cursor", "xdb_password", "xca_db"]
            )
            enrollment_config_log(
                self.logger, self, self.enrollment_config_log_skip_list
            )

        # load template if configured
        if self.template_name:
            dn_dic, template_dic = self._template_load()
        else:
            dn_dic = {}
            template_dic = {}

        # creating a rest from CSR
        req = x509.load_pem_x509_csr(convert_string_to_byte(csr), default_backend())

        # set cert_validity
        if "validity" in template_dic:
            self.logger.debug(
                "Take validity from template: %s", template_dic["validity"]
            )
            # take validity from template
            cert_validity = template_dic["validity"]
        else:
            cert_validity = self.cert_validity_days

        # create object for certificate
        builder = x509.CertificateBuilder()

        # set not valid before
        builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        builder = builder.not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=cert_validity)
        )
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.serial_number(uuid.uuid4().int & (1 << 63) - 1)
        builder = builder.public_key(req.public_key())

        # get extension list from CSR
        csr_extensions_list = req.extensions
        extension_list = self._extension_list_generate(
            template_dic, req, ca_cert, csr_extensions_list
        )

        # add extensions (copy from CSR and take the ones we constructed)
        for extension in extension_list:
            builder = builder.add_extension(
                extension["name"], critical=extension["critical"]
            )

        # get subject and set to builder
        builder = builder.subject_name(
            self._cert_subject_generate(req, request_name, dn_dic)
        )

        # sign certificate
        cert = builder.sign(
            private_key=ca_key, algorithm=hashes.SHA256(), backend=default_backend()
        )

        # get serial
        serial = cert.serial_number
        # get hsshes
        issuer_subject_hash = self._subject_name_hash_get(ca_cert)
        cert_subject_hash = self._subject_name_hash_get(cert)

        # store certificate
        self._store_cert(
            ca_id,
            request_name,
            f"{serial:X}",
            convert_byte_to_string(
                b64_encode(self.logger, cert.public_bytes(serialization.Encoding.DER))
            ),
            cert_subject_hash,
            issuer_subject_hash,
        )

        cert_bundle = self._pemcertchain_generate(
            convert_byte_to_string(cert.public_bytes(serialization.Encoding.PEM)),
            convert_byte_to_string(ca_cert.public_bytes(serialization.Encoding.PEM)),
        )
        cert_raw = convert_byte_to_string(
            b64_encode(self.logger, cert.public_bytes(serialization.Encoding.DER))
        )

        self.logger.debug("Certificate._cert_sign() ended.")
        return (cert_bundle, cert_raw)

    def _columnnames_get(self, table: str) -> List[str]:
        """get columns of a table"""
        self.logger.debug("CAhandler.columns_get(%s)", table)

        self._db_open()
        pre_statement = f"SELECT * from {table} LIMIT 0"
        self.cursor.execute(pre_statement)
        result = [
            column[0].lower() if isinstance(column[0], str) else column[0]
            for column in self.cursor.description
        ]
        self._db_close()

        self.logger.debug(
            "CAhandler.columns_get() ended with: %s elements", len(result)
        )
        return result

    def _xdb_engine_normalized(self) -> str:
        raw = (self.xdb_engine or "sqlite").lower()
        return XDB_ENGINE_MAP.get(raw, raw)

    def _db_configured(self) -> bool:
        """True when sqlite file or remote connection settings are present."""
        if self._xdb_engine_normalized() in ("mysql", "postgresql"):
            return bool(self.xdb_host and self.xdb_name and self.xdb_user)
        return bool(self.xdb_file)

    def _config_check(self) -> str:
        """check config for consitency"""
        self.logger.debug("CAhandler._config_check()")
        error = None
        engine = self._xdb_engine_normalized()

        if engine not in ("sqlite", "mysql", "postgresql"):
            error = f"unsupported xdb_engine {self.xdb_engine}"
        elif engine == "sqlite":
            if self.xdb_file:
                if not os.path.exists(self.xdb_file):
                    error = f"xdb_file {self.xdb_file} does not exist"
                    self.xdb_file = None
            else:
                error = "xdb_file must be specified in config file"
        else:
            if self.xdb_file:
                error = "xdb_file and remote xdb_engine are mutually exclusive"
            elif not self.xdb_host or not self.xdb_name or not self.xdb_user:
                error = (
                    "xdb_host, xdb_name and xdb_user must be specified in config file"
                )
            elif not self.xdb_password:
                error = "xdb_password must be specified in config file"

        if not error and not self.issuing_ca_name:
            error = "issuing_ca_name must be set in config file"

        if error:
            self.logger.debug("CAhandler config error: %s", error)

        if not self.issuing_ca_key:
            self.logger.debug(
                "use self.issuing_ca_name as self.issuing_ca_key: %s",
                self.issuing_ca_name,
            )
            self.issuing_ca_key = self.issuing_ca_name

        self.logger.debug("CAhandler._config_check() ended")
        return error

    def _config_load(self) -> None:
        """load config from file"""
        self.logger.debug("CAhandler._config_load()")
        config_dic = load_config(self.logger, "CAhandler")

        if "CAhandler" in config_dic:
            self.xdb_file = config_dic.get(
                "CAhandler", "xdb_file", fallback=self.xdb_file
            )
            self.xdb_permission = config_dic.get(
                "CAhandler", "xdb_permission", fallback=self.xdb_permission
            )
            engine_raw = config_dic.get("CAhandler", "xdb_engine", fallback="").strip()
            if engine_raw:
                self.xdb_engine = XDB_ENGINE_MAP.get(
                    engine_raw.lower(), engine_raw.lower()
                )
            self.xdb_host = config_dic.get(
                "CAhandler", "xdb_host", fallback=self.xdb_host
            )
            port_raw = config_dic.get("CAhandler", "xdb_port", fallback="")
            if port_raw:
                try:
                    self.xdb_port = int(port_raw)
                except (TypeError, ValueError):
                    self.logger.error('Parameter "xdb_port" cannot be loaded')
            self.xdb_name = config_dic.get(
                "CAhandler", "xdb_name", fallback=self.xdb_name
            )
            self.xdb_user = config_dic.get(
                "CAhandler", "xdb_user", fallback=self.xdb_user
            )
            self.xdb_table_prefix = config_dic.get(
                "CAhandler", "xdb_table_prefix", fallback=self.xdb_table_prefix
            )
            self.xdb_ssl_ca = config_dic.get(
                "CAhandler", "xdb_ssl_ca", fallback=self.xdb_ssl_ca
            )
            self.xdb_ssl_mode = config_dic.get(
                "CAhandler", "xdb_ssl_mode", fallback=self.xdb_ssl_mode
            )
            self.issuing_ca_name = config_dic.get(
                "CAhandler", "issuing_ca_name", fallback=self.issuing_ca_name
            )
            self.issuing_ca_key = config_dic.get(
                "CAhandler", "issuing_ca_key", fallback=self.issuing_ca_key
            )
            self.template_name = config_dic.get(
                "CAhandler", self.profile_mapping_field, fallback=self.template_name
            )

            if "ca_cert_chain_list" in config_dic["CAhandler"]:
                try:
                    self.ca_cert_chain_list = json.loads(
                        config_dic.get("CAhandler", "ca_cert_chain_list")
                    )
                except (json.JSONDecodeError, TypeError):
                    self.logger.error('Parameter "ca_cert_chain_list" cannot be loaded')

        self.passphrase = config_option_load(
            self.logger, config_dic, "passphrase", current=self.passphrase
        )
        self.xdb_password = config_option_load(
            self.logger, config_dic, "xdb_password", current=self.xdb_password
        )
        self._xca_db_configure()

        # load profiling
        self.eab_profiling, self.eab_handler = config_eab_profile_load(
            self.logger, config_dic
        )

        # load profiles
        self.profiles = config_profile_load(self.logger, config_dic)

        # load header info
        self.header_info_field = config_headerinfo_load(self.logger, config_dic)

        # load enrollment config log
        (
            self.enrollment_config_log,
            self.enrollment_config_log_skip_list,
        ) = config_enroll_config_log_load(self.logger, config_dic)

    def _csr_import(self, csr, request_name):
        """check existance of csr and load into db"""
        self.logger.debug("CAhandler._csr_import()")

        csr_info = self._csr_search("request", csr)

        if not csr_info:

            # csr does not exist in db - lets import it
            insert_date = uts_to_date_utc(uts_now(), DEFAULT_DATE_FORMAT)
            item_dic = {
                "type": 2,
                "comment": "from acme2certifier",
                "source": 2,
                "date": insert_date,
                "name": request_name,
            }
            row_id = self._item_insert(item_dic)

            # insert csr
            csr_info = {"item": row_id, "signed": 1, "request": csr}
            self._csr_insert(csr_info)
            if row_id:
                self._x509super_store_from_csr(csr, row_id)

        self.logger.debug("CAhandler._csr_import() ended")
        return csr_info

    def _csr_insert(self, csr_dic: Dict[str, str] = None) -> int:
        """insert new entry to request table"""
        self.logger.debug("CAhandler._csr_insert()")
        row_id = None
        if csr_dic:
            if all(key in csr_dic for key in ("item", "signed", "request")):
                # item and signed must be integer
                if isinstance(csr_dic["item"], int) and isinstance(
                    csr_dic["signed"], int
                ):
                    self._db_open()
                    self.cursor.execute(
                        """INSERT INTO requests(item, signed, request) VALUES(:item, :signed, :request)""",
                        csr_dic,
                    )
                    row_id = self._inserted_row_id()
                    self._db_close()
                else:
                    self.logger.error(
                        "CSR insert aborted due to wrong datatypes: %s", csr_dic
                    )
            else:
                self.logger.error(
                    "CSR insert aborted due to incomplete dataset: %s", csr_dic
                )
        else:
            self.logger.error("CSR insert aborted: dataset is empty")

        self.logger.debug("CAhandler._csr_insert() ended with row_id: %s", row_id)
        return row_id

    def _csr_search(self, column: str, value: str) -> Dict[str, str]:
        """load ca key from database"""
        self.logger.debug("CAhandler._csr_search()")

        if not self._identifier_check("view_requests", column):
            self.logger.warning(COLUMN_NOT_IN_TABLE_MSG, column, "view_requests")
            return {}

        # query database for key
        self._db_open()
        pre_statement = f"""SELECT * from view_requests WHERE {column} LIKE ?"""
        self.cursor.execute(pre_statement, [value])

        row = self.cursor.fetchone()
        try:
            db_result = dict_from_row(row)
        except Exception as err:
            self.logger.error("CSR search in database failed: %s", err)
            db_result = {}
        self._db_close()
        self.logger.debug("CAhandler._csr_search() ended with: %s", bool(db_result))
        return db_result

    def _db_check(self):
        """do various checks on database"""
        self.logger.debug("CAhandler._db_check()")
        error = None

        if self._xdb_engine_normalized() == "sqlite":
            st = os.stat(self.xdb_file)
            oct_perm = oct(st.st_mode)[-3:]

            if not os.access(self.xdb_file, os.R_OK):
                error = f"xdb_file {self.xdb_file} is not readable"
            elif not os.access(self.xdb_file, os.W_OK):
                error = f"xdb_file {self.xdb_file} is not writeable"
            elif (
                int(oct_perm[0]) > int(self.xdb_permission[0])
                or int(oct_perm[1]) > int(self.xdb_permission[1])
                or int(oct_perm[2]) > int(self.xdb_permission[2])
            ):
                self.logger.warning(
                    "File permissions %s for '%s' are too permissive. Should be %s.",
                    oct_perm,
                    self.xdb_file,
                    self.xdb_permission,
                )
        else:
            try:
                self._db_open()
                self.cursor.execute("SELECT 1")
                self.cursor.fetchone()
                self._db_close()
            except Exception as err:
                error = f"database connection failed: {err}"

        if not error:
            ca_key = self._ca_key_load()
            if not ca_key:
                error = "ca_key_load failed. Please check passphrase"

        self.logger.debug("CAhandler._db_check() ended with: %s", error)
        return error

    def _xca_db_configure(self) -> None:
        self.xca_db.configure(
            engine=self._xdb_engine_normalized(),
            xdb_file=self.xdb_file,
            host=self.xdb_host,
            port=self.xdb_port,
            name=self.xdb_name,
            user=self.xdb_user,
            password=self.xdb_password,
            table_prefix=self.xdb_table_prefix,
            ssl_ca=self.xdb_ssl_ca,
            ssl_mode=self.xdb_ssl_mode,
        )

    def _db_open(self) -> None:
        """opens db and sets cursor; nested calls reuse the connection"""
        if self._db_refcount == 0:
            self._xca_db_configure()
            self.dbs, self.cursor = self.xca_db.connect()
        self._db_refcount += 1

    def _db_close(self):
        """commit on the outermost close and disconnect"""
        if self._db_refcount > 0:
            self._db_refcount -= 1
        if self._db_refcount == 0:
            if self.dbs is not None:
                self.dbs.commit()
            self._db_disconnect()

    def _db_disconnect(self) -> None:
        if self.dbs is not None:
            try:
                self.dbs.close()
            except Exception as err:
                self.logger.error("Failed to close XCA database connection: %s", err)
            self.dbs = None
            self.cursor = None
            self.xca_db.connection = None

    def _extended_keyusage_generate(
        self, template_dic: Dict[str, str], _csr_extensions_dic: Dict[str, str] = None
    ) -> Tuple[bool, List[str]]:
        """set generate extended key usage extenstion"""
        self.logger.debug("CAhandler._extended_keyusage_generate()")

        eku_list = []
        if "eKeyUse" in template_dic:
            # eku included in tempalate
            eku_mapping_dic = {
                "clientAuth": ExtendedKeyUsageOID.CLIENT_AUTH,
                "serverAuth": ExtendedKeyUsageOID.SERVER_AUTH,
                "codeSigning": ExtendedKeyUsageOID.CODE_SIGNING,
                "emailProtection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
                "timeStamping": ExtendedKeyUsageOID.TIME_STAMPING,
                "OCSPSigning": ExtendedKeyUsageOID.OCSP_SIGNING,
                "eKeyUse": "eKeyUse",  # this is just for testing
            }
            # backwards compatibility with cryptography module coming Ubuntu 22.04
            if hasattr(ExtendedKeyUsageOID, "KERBEROS_PKINIT_KDC"):
                eku_mapping_dic["pkInitKDC"] = ExtendedKeyUsageOID.KERBEROS_PKINIT_KDC

            if "ekuCritical" in template_dic:
                try:
                    ekuc = bool(int(template_dic["ekuCritical"]))
                except (TypeError, ValueError):
                    self.logger.error(
                        "Failed to convert EKU critical flag to int, defaulting to False"
                    )
                    ekuc = False
            else:
                ekuc = False

            for ele in template_dic["eKeyUse"].split(", "):
                if ele in eku_mapping_dic:
                    eku_list.append(eku_mapping_dic[ele])

        else:
            # neither extension nor template
            eku_list = None
            ekuc = False

        return (ekuc, eku_list)

    def _extension_list_default(self, ca_cert: str = None, cert: str = None):
        """set default extension list"""
        self.logger.debug("CAhandler._extension_list_default()")

        extension_list = [
            {"name": BasicConstraints(ca=False, path_length=None), "critical": True},
            {
                "name": KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                "critical": True,
            },
            {
                "name": ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                "critical": False,
            },
        ]
        if cert:
            extension_list.append(
                {
                    "name": SubjectKeyIdentifier.from_public_key(cert.public_key()),
                    "critical": False,
                },
            )
        if ca_cert:
            extension_list.append(
                {
                    "name": AuthorityKeyIdentifier.from_issuer_public_key(
                        ca_cert.public_key()
                    ),
                    "critical": False,
                }
            )

        self.logger.debug("CAhandler._extension_list_default() ended")
        return extension_list

    def _extension_list_generate(
        self,
        template_dic: Dict[str, str],
        cert: str,
        ca_cert: str,
        csr_extensions_list: List[str] = None,
    ) -> List[str]:
        """set extension list"""
        self.logger.debug("CAhandler._extension_list_generate()")

        csr_extensions_dic = {}
        if csr_extensions_list:
            for ext in csr_extensions_list:
                csr_extensions_dic[convert_byte_to_string(ext.oid._name)] = (
                    ext  # pylint: disable=W0212
                )

        if template_dic:
            # prcoess xca template
            extension_list = self._xca_template_process(
                template_dic, csr_extensions_dic, cert, ca_cert
            )
        else:
            extension_list = self._extension_list_default(ca_cert, cert)

        # add subjectAltName(s)
        if "subjectAltName" in csr_extensions_dic:
            # pylint: disable=C2801
            self.logger.debug(
                "CAhandler._extension_list_generate(): adding subAltNames: %s",
                csr_extensions_dic["subjectAltName"].__str__(),
            )
            extension_list.append(
                {
                    "name": SubjectAlternativeName(
                        csr_extensions_dic["subjectAltName"].value
                    ),
                    "critical": False,
                }
            )

        self.logger.debug("CAhandler._extension_list_generate() ended")
        return extension_list

    def _identifier_check(self, table: str, identifier: str) -> bool:
        """check if identifier is in table"""
        self.logger.debug("CAhandler._identifier_check(%s, %s)", identifier, table)
        if "." in identifier:
            # we have a table.column name
            table, identifier = identifier.split(".", 1)
            self.logger.debug(
                "CAhandler._identifier_check(): modified table/identifier to %s/%s",
                table,
                identifier,
            )
        elif "__" in identifier:
            # we have a table__column name
            table, identifier = identifier.split("__", 1)
            self.logger.debug(
                "CAhandler._identifier_check(): modified table/identifier to %s/%s",
                table,
                identifier,
            )
        if self._table_check(table):
            columnname_list = self._columnnames_get(table)
            result = True if identifier in columnname_list else False
        else:
            self.logger.warning("Table '%s' does not exist in the database.", table)
            result = False

        self.logger.debug("CAhandler._identifier_check() ended with: %s", result)
        return result

    def _item_insert(self, item_dic: Dict[str, str] = None) -> int:
        """insert new entry to item_table"""
        self.logger.debug("CAhandler._item_insert()")
        row_id = None
        # insert
        if item_dic:
            if all(
                key in item_dic for key in ("name", "type", "source", "date", "comment")
            ):
                if isinstance(item_dic["type"], int) and isinstance(
                    item_dic["source"], int
                ):
                    self._db_open()
                    row_id = self._next_item_id()
                    insert_dic = dict(item_dic)
                    insert_dic["id"] = row_id
                    self.cursor.execute(
                        """INSERT INTO items(id, name, type, source, date, comment) VALUES(:id, :name, :type, :source, :date, :comment)""",
                        insert_dic,
                    )
                    self.cursor.execute(
                        """UPDATE items SET stamp = :stamp WHERE id = :stamp""",
                        {"stamp": row_id},
                    )
                    self._db_close()
                else:
                    self.logger.error(
                        "Item insert aborted due to wrong datatypes: %s", item_dic
                    )
            else:
                self.logger.error(
                    "Item insert aborted due to incomplete dataset: %s", item_dic
                )
        else:
            self.logger.error("Item insert aborted: dataset is empty")

        self.logger.debug("CAhandler._item_insert() ended with row_id: %s", row_id)
        return row_id

    def _inserted_row_id(self) -> Optional[int]:
        """lastrowid, or 1 when the insert succeeded without an autoincrement id."""
        self.logger.debug("CAhandler._inserted_row_id()")
        row_id = self.cursor.lastrowid
        if row_id:
            return int(row_id)
        if getattr(self.cursor, "rowcount", 0) > 0:
            return 1
        return None

    def _next_item_id(self) -> int:
        """allocate the next items.id (portable across SQLite/MySQL/PostgreSQL)"""
        self.logger.debug("CAhandler._next_item_id()")
        self.cursor.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM items")
        value = self._row_first_value(self.cursor.fetchone())
        self.logger.debug("CAhandler._next_item_id() ended with value: %s", value)
        return int(value or 1)

    def _row_first_value(self, row: Any) -> Any:
        self.logger.debug("CAhandler._row_first_value()")
        if row is None:
            return None
        if isinstance(row, dict):
            return next(iter(row.values()))
        return row[0]

    def _keyusage_generate(
        self, template_dic: Dict[str, str], _csr_extensions_dic: Dict[str, str] = None
    ) -> Tuple[bool, Dict[str, str]]:
        """set generate key usage extenstion"""
        self.logger.debug("CAhandler._keyusage_generate()")

        if "keyUse" in template_dic:
            if "kuCritical" in template_dic:
                try:
                    kuc = bool(int(template_dic["kuCritical"]))
                except (TypeError, ValueError):
                    kuc = False
            else:
                kuc = False
            kup = template_dic["keyUse"]
        else:
            kuc = False
            kup = 0

        # generate key-usage extension
        ku_dic = self._kue_generate(kup)

        return (kuc, ku_dic)

    def _kue_generate(self, kuval: int = 0, ku_csr: str = None) -> Dict[str, str]:
        """set generate key usage extension"""
        self.logger.debug("CAhandler._kue_generate()")

        # convert keyusage value from template
        if kuval:
            try:
                kuval = int(kuval)
            except (TypeError, ValueError):
                self.logger.error(
                    "Keyusage value conversion to int failed, defaulting to 0"
                )
                kuval = 0

        if kuval:
            # we have a key-usage value from template
            self.logger.debug("Generate KeyUsage Extension with data from template")
            ku_dic = self._ku_dict_generate(kuval)
        elif ku_csr:
            # no data from template but data from csr
            self.logger.debug("Generate KeyUsage Extension with data from csr")
            ku_dic = ku_csr
        else:
            # no data from template no data from csr - default (23)
            self.logger.debug("Generate KeyUsage Extension with value 23")
            ku_dic = self._ku_dict_generate(23)

        self.logger.debug("CAhandler._kue_generate() ended with: %s", ku_dic)
        return ku_dic

    def _ku_dict_generate(self, kuval: int = 0) -> Dict[str, str]:
        self.logger.debug("CAhandler._ku_dict_generate(%s)", kuval)

        # generate and reverse key_usage_list
        key_usage_list = [
            "digital_signature",
            "content_commitment",
            "key_encipherment",
            "data_encipherment",
            "key_agreement",
            "key_cert_sign",
            "crl_sign",
            "encipher_only",
            "decipher_only",
        ]
        key_usage_dic = {
            "digital_signature": False,
            "content_commitment": False,
            "key_encipherment": False,
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        }

        kubin = f"{kuval:b}"[::-1]
        for idx, ele in enumerate(kubin):
            if ele == "1":
                key_usage_dic[key_usage_list[idx]] = True

        self.logger.debug("CAhandler._ku_dict_generate() ended with: %s", key_usage_dic)
        return key_usage_dic

    def _pemcertchain_generate(self, ee_cert: str, issuer_cert: str = None) -> str:
        """build pem chain"""
        self.logger.debug("CAhandler._pemcertchain_generate()")

        if issuer_cert:
            pem_chain = f"{ee_cert}{issuer_cert}"
        else:
            pem_chain = ee_cert

        for cert in self.ca_cert_chain_list:
            cert_dic = self._cert_search("items.name", cert)
            if cert_dic and "cert" in cert_dic:
                ca_cert = x509.load_der_x509_certificate(
                    b64_decode(self.logger, cert_dic["cert"]), backend=default_backend()
                )
                pem_chain = f"{pem_chain}{convert_byte_to_string(ca_cert.public_bytes(serialization.Encoding.PEM))}"

        self.logger.debug("CAhandler._pemcertchain_generate() ended")
        return pem_chain

    def _requestname_get(self, csr: str = None) -> str:
        """get request name"""
        self.logger.debug("CAhandler._requestname_get()")

        # try to get cn for a name in database
        request_name = csr_cn_get(self.logger, csr)
        if not request_name:
            san_list = csr_san_get(self.logger, csr)
            try:
                (
                    _identifiier,
                    request_name,
                ) = san_list[
                    0
                ].split(":")
            except (AttributeError, IndexError, ValueError):
                self.logger.error(
                    "Failed to split SAN from CSR subjectAltName: %s", san_list
                )

        self.logger.debug("CAhandler._requestname_get() ended with: %s", request_name)
        return request_name

    def _revocation_insert(self, rev_dic: Dict[str, str] = None) -> int:
        """insert new entry to into revocation_table"""
        self.logger.debug("CAhandler._revocation_insert()")
        row_id = None
        # insert
        if rev_dic:
            if all(
                key in rev_dic
                for key in ("caID", "serial", "date", "invaldate", "reasonBit")
            ):
                if isinstance(rev_dic["caID"], int) and isinstance(
                    rev_dic["reasonBit"], int
                ):
                    self._db_open()
                    self.cursor.execute(
                        """INSERT INTO revocations(caID, serial, date, invaldate, reasonBit) VALUES(:caID, :serial, :date, :invaldate, :reasonBit)""",
                        rev_dic,
                    )
                    row_id = self._inserted_row_id()
                    self._db_close()
                else:
                    self.logger.error(
                        "Revocation insert aborted due to wrong datatypes: %s", rev_dic
                    )
            else:
                self.logger.error(
                    "Revocation insert aborted due to incomplete dataset: %s", rev_dic
                )
        else:
            self.logger.error("Revocation insert aborted: dataset is empty")

        self.logger.debug(
            "CAhandler._revocation_insert() ended with row_id: %s", row_id
        )
        return row_id

    def _revocation_check(
        self, serial: str, ca_id: int, err_msg_dic: Dict[str, str] = None
    ) -> Tuple[int, str, str]:
        self.logger.debug("CAhandler.revoke(%s/%s)", serial, ca_id)

        # check if certificate has alreay been revoked:
        if not self._revocation_search("serial", serial):
            rev_dic = {
                "caID": ca_id,
                "serial": serial,
                "date": uts_to_date_utc(uts_now(), DEFAULT_DATE_FORMAT),
                "invaldate": uts_to_date_utc(uts_now(), DEFAULT_DATE_FORMAT),
                "reasonBit": 0,
            }
            row_id = self._revocation_insert(rev_dic)
            if row_id:
                code = 200
                message = None
                detail = None
            else:
                code = 500
                message = err_msg_dic["serverinternal"]
                detail = "database update failed"
        else:
            code = 400
            message = err_msg_dic["alreadyrevoked"]
            detail = "Certificate has already been revoked"

        self.logger.debug("CAhandler.revoke() ended with: %s", code)
        return (code, message, detail)

    def _revocation_search(self, column: str, value: str) -> Dict[str, str]:
        """load ca key from database"""
        self.logger.debug("CAhandler._revocation_search()")

        if not self._identifier_check("revocations", column):
            self.logger.warning(COLUMN_NOT_IN_TABLE_MSG, column, "revocations")
            return {}
        # query database for key
        self._db_open()
        pre_statement = f"""SELECT * from revocations WHERE {column} LIKE ?"""
        self.cursor.execute(pre_statement, [value])

        row = self.cursor.fetchone()
        try:
            db_result = dict_from_row(row)
        except Exception as err:
            self.logger.error("Revocation search in database failed: %s", err)
            db_result = {}
        self._db_close()
        self.logger.debug("CAhandler._revocation_search() ended")
        return db_result

    # pylint: disable=R0913
    def _store_cert(
        self,
        ca_id: int,
        cert_name: str,
        serial: str,
        cert: str,
        name_hash: str,
        issuer_hash: str,
    ) -> int:
        """store certificate to database"""
        self.logger.debug("CAhandler._store_cert()")

        # insert certificate into item table
        insert_date = uts_to_date_utc(uts_now(), DEFAULT_DATE_FORMAT)
        item_dic = {
            "type": 3,
            "comment": "from acme2certifier",
            "source": 2,
            "date": insert_date,
            "name": cert_name,
        }
        row_id = self._item_insert(item_dic)
        # insert certificate to cert table
        cert_dic = {
            "item": row_id,
            "serial": serial,
            "issuer": ca_id,
            "ca": 0,
            "cert": cert,
            "iss_hash": issuer_hash,
            "hash": name_hash,
        }
        _row_id = self._cert_insert(cert_dic)  # lgtm [py/unused-local-variable]
        if row_id:
            self._x509super_store_from_cert(cert, row_id, name_hash)

        self.logger.debug("CAhandler._store_cert() ended")

    def _stream_split(self, byte_stream: str = None) -> Tuple[str, str]:
        """split template in asn1 structure and utf_stream"""
        self.logger.debug("CAhandler._stream_split()")
        asn1_stream = None
        utf_stream = None

        # convert to byte if not already done
        byte_stream = convert_string_to_byte(byte_stream)

        if byte_stream:
            # search pattern
            pos = byte_stream.find(b"\x00\x00\x00\x0c") + 4
            if pos != 3:
                # split file 3 bcs find returns -1 in case of no-match
                asn1_stream = byte_stream[:pos]
                utf_stream = byte_stream[pos:]

        self.logger.debug(
            "CAhandler._stream_split() ended: %s:%s",
            bool(asn1_stream),
            bool(utf_stream),
        )
        return (asn1_stream, utf_stream)

    def _stub_func(self, parameter: str) -> str:
        """ " load config from file"""
        self.logger.debug("CAhandler._stub_func(%s)", parameter)
        self.logger.debug("CAhandler._stub_func() ended")
        return parameter

    def _subject_name_hash_get(self, cert: str = None) -> int:
        """get subject name hash"""
        self.logger.debug("CAhandler._subject_name_hash_get()")

        pyopenssl_cert = pyossslcrypto.X509.from_cryptography(cert)
        pyopenssl_subject_name_hash = pyopenssl_cert.subject_name_hash() & 0x7FFFFFFF

        return pyopenssl_subject_name_hash

    def _public_key_hash_get(self, public_key: object) -> int:
        """XCA 32-bit key hash (SHA1(SPKI)[:4] little-endian, 31-bit)."""
        self.logger.debug("CAhandler._public_key_hash_get()")
        spki = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        digest = hashlib.sha1(spki).digest()[:4]
        return int.from_bytes(digest, "little") & 0x7FFFFFFF

    def _x509super_insert(
        self, x509_dic: Optional[Dict[str, Any]] = None
    ) -> Optional[int]:
        """insert x509super row used by XCA views"""
        self.logger.debug("CAhandler._x509super_insert()")
        row_id = None
        if x509_dic and all(
            key in x509_dic for key in ("item", "subj_hash", "key_hash")
        ):
            if (
                isinstance(x509_dic["item"], int)
                and isinstance(x509_dic["subj_hash"], int)
                and isinstance(x509_dic["key_hash"], int)
            ):
                payload = {
                    "item": x509_dic["item"],
                    "subj_hash": x509_dic["subj_hash"],
                    "pkey": x509_dic.get("pkey"),
                    "key_hash": x509_dic["key_hash"],
                }
                self._db_open()
                self.cursor.execute(
                    """INSERT INTO x509super(item, subj_hash, pkey, key_hash) VALUES(:item, :subj_hash, :pkey, :key_hash)""",
                    payload,
                )
                row_id = self._inserted_row_id()
                self._db_close()
            else:
                self.logger.error(
                    "x509super insert aborted due to wrong datatypes: %s", x509_dic
                )
        else:
            self.logger.error(
                "x509super insert aborted due to incomplete dataset: %s", x509_dic
            )
        self.logger.debug("CAhandler._x509super_insert() ended with row_id: %s", row_id)
        return row_id

    def _x509super_store_from_csr(self, csr: str, item_id: int) -> None:
        """best-effort x509super row for an imported CSR"""
        self.logger.debug("CAhandler._x509super_store_from_csr(%s)", item_id)
        try:
            csr_pem = build_pem_file(
                self.logger, None, b64_url_recode(self.logger, csr), None, True
            )
            req = x509.load_pem_x509_csr(
                convert_string_to_byte(csr_pem), default_backend()
            )
            pyreq = pyossslcrypto.load_certificate_request(
                pyossslcrypto.FILETYPE_PEM, convert_string_to_byte(csr_pem)
            )
            self._x509super_insert(
                {
                    "item": item_id,
                    "subj_hash": pyreq.get_subject().hash() & 0x7FFFFFFF,
                    "pkey": None,
                    "key_hash": self._public_key_hash_get(req.public_key()),
                }
            )
        except Exception as err:
            self.logger.error("Failed to store x509super for CSR: %s", err)

    def _x509super_store_from_cert(
        self, cert_b64: str, item_id: int, subj_hash: Any
    ) -> None:
        """best-effort x509super row for a stored certificate"""
        self.logger.debug("CAhandler._x509super_store_from_cert(%s)", item_id)
        try:
            cert = x509.load_der_x509_certificate(
                b64_decode(self.logger, cert_b64), default_backend()
            )
            self._x509super_insert(
                {
                    "item": item_id,
                    "subj_hash": int(subj_hash),
                    "pkey": None,
                    "key_hash": self._public_key_hash_get(cert.public_key()),
                }
            )
        except Exception as err:
            self.logger.error("Failed to store x509super for certificate: %s", err)

    def _subject_modify(self, subject: str, dn_dic: Dict[str, str] = None) -> str:
        """modify subject name"""
        self.logger.debug("CAhandler._subject_modify()")

        subject_name_list = []

        if "organizationalUnitName" in dn_dic and dn_dic["organizationalUnitName"]:
            self.logger.info("Rewrite OU to %s", dn_dic["organizationalUnitName"])
            subject_name_list.append(
                x509.NameAttribute(
                    x509.NameOID.ORGANIZATIONAL_UNIT_NAME,
                    dn_dic["organizationalUnitName"],
                )
            )
        if "organizationName" in dn_dic and dn_dic["organizationName"]:
            self.logger.info("Rewrite O to %s", dn_dic["organizationName"])
            subject_name_list.append(
                x509.NameAttribute(
                    x509.NameOID.ORGANIZATION_NAME, dn_dic["organizationName"]
                )
            )
        if "localityName" in dn_dic and dn_dic["localityName"]:
            self.logger.info("Rewrite L to %s", dn_dic["localityName"])
            subject_name_list.append(
                x509.NameAttribute(x509.NameOID.LOCALITY_NAME, dn_dic["localityName"])
            )
        if "stateOrProvinceName" in dn_dic and dn_dic["stateOrProvinceName"]:
            self.logger.info("Rewrite ST to %s", dn_dic["stateOrProvinceName"])
            subject_name_list.append(
                x509.NameAttribute(
                    x509.NameOID.STATE_OR_PROVINCE_NAME, dn_dic["stateOrProvinceName"]
                )
            )
        if "countryName" in dn_dic and dn_dic["countryName"]:
            self.logger.info("Rewrite C to %s", dn_dic["countryName"])
            subject_name_list.append(
                x509.NameAttribute(x509.NameOID.COUNTRY_NAME, dn_dic["countryName"])
            )

        if subject_name_list:
            subject = x509.Name([*subject, *subject_name_list])

        self.logger.debug("CAhandler._subject_modify() ended")
        return subject

    def _table_check(self, table: str) -> bool:
        """get all tables in db"""
        self.logger.debug("DBStore.tables_get()")
        self._db_open()
        self.cursor.execute(self.xca_db.catalog_sql())
        tables_list = [
            str(self._row_first_value(row)).lower()
            for row in self.cursor.fetchall()
            if row is not None
        ]
        self._db_close()
        physical = self.xca_db.physical_name(table).lower()
        result = physical in tables_list
        self.logger.debug("DBStore._table_check() ended with: %s", result)
        return result

    def _template_load(self) -> Tuple[Dict[str, str], Dict[str, str]]:
        """load template from database"""
        self.logger.debug("CAhandler._template_load(%s)", self.template_name)
        # query database for template
        self._db_open()
        pre_statement = """SELECT * from view_templates WHERE name LIKE ?"""
        self.cursor.execute(pre_statement, [self.template_name])
        row = self.cursor.fetchone()
        try:
            db_result = dict_from_row(row)
        except Exception as err:
            self.logger.error("template lookup failed: %s", err)
            db_result = {}

        # parse template
        dn_dic = {}
        template_dic = {}
        if "template" in db_result:
            byte_stream = b64_decode(self.logger, db_result["template"])
            dn_dic, template_dic = self._template_parse(byte_stream)
        self._db_close()
        self.logger.debug("CAhandler._template_load() ended")

        return (dn_dic, template_dic)

    def _template_parse(
        self, byte_string: str = None
    ) -> Tuple[Dict[str, str], Dict[str, str]]:
        """process template"""
        self.logger.debug("CAhandler._template_parse()")
        asn1_stream, utf_stream = self._stream_split(byte_string)

        dn_dic = {}
        if asn1_stream:
            dn_dic = self._asn1_stream_parse(asn1_stream)

        template_dic = {}
        if utf_stream:
            template_dic = self._utf_stream_parse(utf_stream)
            if template_dic:
                # replace '' with None
                template_dic = {
                    k: None if not v else v for k, v in template_dic.items()
                }

                template_dic["validity"] = self._validity_calculate(template_dic)

        self.logger.debug("CAhandler._template_parse() ended")
        return (dn_dic, template_dic)

    def _utf_stream_parse(self, utf_stream: str = None) -> Dict[str, str]:
        """parse template information from utf_stream into dictitionary"""
        self.logger.debug("CAhandler._utf_stream_parse()")
        template_dic = {}

        if utf_stream:
            stream_list = utf_stream.split(b"\x00\x00\x00")

            # iterate list and clean up parameter
            parameter_list = []
            for idx, ele in enumerate(stream_list):
                ele = ele.replace(b"\x00", b"")
                if idx > 0:
                    # strip the first character
                    ele = ele[1:]
                if ele == b"eKeyUse\xff\xff\xff\xff":
                    self.logger.info(
                        "Hack to skip template with empty eku - maybe a bug in xca..."
                    )
                else:
                    parameter_list.append(ele.decode("utf-8"))

            if parameter_list:
                if len(parameter_list) % 2 != 0:
                    # remove last element from list if amount of list entries is uneven
                    parameter_list.pop()
                # convert list into a directory
                template_dic = {
                    item: parameter_list[index + 1]
                    for index, item in enumerate(parameter_list)
                    if index % 2 == 0
                }

        self.logger.debug("CAhandler._utf_stream_parse() ended: %s", bool(template_dic))
        return template_dic

    def _validity_calculate(self, template_dic: Dict[str, str] = None) -> int:
        """calculate validity in days"""
        self.logger.debug("CAhandler._validity_calculate()")

        cert_validity = 365
        if "validM" in template_dic and "validN" in template_dic:
            if template_dic["validM"] == "0":
                # validity in days
                cert_validity = int(template_dic["validN"])
            elif template_dic["validM"] == "1":
                # validity in months
                cert_validity = int(template_dic["validN"]) * 30
            elif template_dic["validM"] == "2":
                # validity in months
                cert_validity = int(template_dic["validN"]) * 365
        else:
            cert_validity = 365

        self.logger.debug(
            "CAhandler._validity_calculate() ended with: %s", cert_validity
        )
        return cert_validity

    def _xca_template_process(
        self,
        template_dic: Dict[str, str],
        csr_extensions_dic: Dict[str, str],
        cert: str,
        ca_cert: str,
    ) -> List[str]:
        """add xca template"""
        self.logger.debug("Certificate._xca_template_process()")

        extension_list = [
            {
                "name": SubjectKeyIdentifier.from_public_key(cert.public_key()),
                "critical": False,
            },
            {
                "name": AuthorityKeyIdentifier.from_issuer_public_key(
                    ca_cert.public_key()
                ),
                "critical": False,
            },
        ]

        # key_usage
        kuc, ku_dic = self._keyusage_generate(template_dic, csr_extensions_dic)
        extension_list.append({"name": KeyUsage(**ku_dic), "critical": kuc})

        # extended key_usage
        ekuc, eku_list = self._extended_keyusage_generate(
            template_dic, csr_extensions_dic
        )
        if eku_list:
            extension_list.append(
                {"name": ExtendedKeyUsage(eku_list), "critical": ekuc}
            )

        # add cdp
        if "crlDist" in template_dic and template_dic["crlDist"]:
            cdp_list = self._cdp_list_generate(template_dic["crlDist"])
            extension_list.append(
                {"name": x509.CRLDistributionPoints(cdp_list), "critical": False}
            )

        # add basicConstraints
        if "ca" in template_dic:
            if "bcCritical" in template_dic:
                try:
                    bcc = bool(int(template_dic["bcCritical"]))
                except (TypeError, ValueError):
                    bcc = False
            else:
                bcc = False

            if template_dic["ca"] == "1":
                extension_list.append(
                    {
                        "name": BasicConstraints(ca=True, path_length=None),
                        "critical": bcc,
                    }
                )
            elif template_dic["ca"] == "2":
                extension_list.append(
                    {
                        "name": BasicConstraints(ca=False, path_length=None),
                        "critical": bcc,
                    }
                )

        return extension_list

    def handler_check(self):
        """check if handler is ready"""
        self.logger.debug("CAhandler.check()")

        error = self._config_check()
        if not error:
            error = self._db_check()

        self.logger.debug("CAhandler.check() ended with %s", error)
        return error

    def enroll(self, csr: str = None) -> Tuple[str, str, str, str]:
        """enroll certificate"""
        # pylint: disable=R0914, R0915
        self.logger.debug("CAhandler.enroll()")

        cert_bundle = None
        cert_raw = None
        error = self._config_check()

        if not error:
            error = self._db_check()

        # fmt: off
        if not error:
            error = eab_profile_header_info_check(self.logger, self, csr, self.profile_mapping_field)
        # fmt: on

        db_session = bool(not error and self._db_configured())
        if db_session:
            self._db_open()
        try:
            if not error:
                request_name = self._requestname_get(csr)

                if request_name:
                    # import CSR to database
                    _csr_info = self._csr_import(
                        csr, request_name
                    )  # lgtm [py/unused-local-variable]

                    # prepare the CSR to be signed
                    csr = build_pem_file(
                        self.logger, None, b64_url_recode(self.logger, csr), None, True
                    )

                    # load ca cert and key
                    ca_key, ca_cert, ca_id = self._ca_load()

                    if ca_key and ca_cert and ca_id:
                        cert_bundle, cert_raw = self._cert_sign(
                            csr, request_name, ca_key, ca_cert, ca_id
                        )
                    else:
                        error = "ca lookup failed"
                else:
                    error = "request_name lookup failed"
        finally:
            if db_session:
                self._db_close()
        self.logger.debug("Certificate.enroll() ended")
        return (error, cert_bundle, cert_raw, None)

    def poll(
        self, cert_name: str, poll_identifier: str, _csr: str
    ) -> Tuple[str, str, str, str, bool]:
        """poll status of pending CSR and download certificates"""
        self.logger.debug("CAhandler.poll()")

        error = "Method not implemented."
        cert_bundle = None
        cert_raw = None
        rejected = False
        self._stub_func(cert_name)

        self.logger.debug("CAhandler.poll() ended")
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(
        self, cert: str, _rev_reason: str = "unspecified", _rev_date: str = None
    ) -> Tuple[int, str, str]:
        """revoke certificate"""
        self.logger.debug("CAhandler.revoke()")

        err_msg_dic = error_dic_get(self.logger)

        # modify handler configuration in case of eab profiling
        if self.eab_profiling:
            eab_profile_revocation_check(self.logger, self, cert)

        if self._db_configured():
            self._db_open()
            try:
                _ca_key, _ca_cert, ca_id = self._ca_load()

                serial = cert_serial_get(self.logger, cert)
                if serial:
                    serial = f"{serial:X}"

                if ca_id and serial:
                    code, message, detail = self._revocation_check(
                        serial, ca_id, err_msg_dic
                    )
                else:
                    code = 500
                    message = err_msg_dic["serverinternal"]
                    detail = "certificate lookup failed"
            finally:
                self._db_close()
        else:
            code = 500
            message = err_msg_dic["serverinternal"]
            detail = CONFIGURATION_ERROR_DETAIL

        self.logger.debug("Certificate.revoke() ended")
        return (code, message, detail)

    def trigger(self, payload: str) -> Tuple[str, str, str]:
        """process trigger message and return certificate"""
        self.logger.debug("CAhandler.trigger()")

        error = "Method not implemented."
        cert_bundle = None
        cert_raw = None
        self._stub_func(payload)

        self.logger.debug("CAhandler.trigger() ended with error: %s", error)
        return (error, cert_bundle, cert_raw)
