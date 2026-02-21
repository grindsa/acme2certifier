#!/usr/bin/python

# -*- coding: utf-8 -*-
"""eab sql handler"""

from __future__ import print_function

from logging import Logger
import psycopg2
import re
from mssql_python import connect
from typing import Dict, List, Optional, Tuple

from acme_srv.helper import load_config, csr_cn_get, csr_san_get


class EABhandler(object):
    """EAB SQL handler"""

    def __init__(self, logger: Logger):
        self.logger = logger

        self.db_system = None
        self.db_host = None
        self.db_name = None
        self.db_user = None
        self.db_password = None

    def __enter__(self):
        """Makes EABhandler a Context Manager"""
        self._config_load()
        return self

    def __exit__(self, *args):
        """Close the connection at the end of the context"""

    def _config_load(self):
        """Load config from file"""
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

    def _chk_san_lists_get(self, csr: str) -> Tuple[List[str], List[bool]]:
        """Check lists"""
        self.logger.debug("EABhandler._chk_san_lists_get()")

        # get sans and build a list
        _san_list = csr_san_get(self.logger, csr)

        check_list = []
        san_list = []

        if _san_list:
            for san in _san_list:
                try:
                    # SAN list must be modified/filtered)
                    (_san_type, san_value) = san.lower().split(":")
                    san_list.append(san_value)
                except Exception:
                    # force check to fail as something went wrong during parsing
                    check_list.append(False)
                    self.logger.info(
                        "SAN list parsing failed at entry: {0}".format(san)
                    )

        self.logger.debug("EABhandler._chk_san_lists_get() ended")
        return (san_list, check_list)

    def _cn_add(self, csr: str, san_list: List[str]) -> Tuple[List[str], str]:
        """Add CN if required"""
        self.logger.debug("EABhandler._cn_add()")

        # get common name and attach it to san_list
        cn_ = csr_cn_get(self.logger, csr)

        if cn_:
            cn_ = cn_.lower()
            if cn_ not in san_list:
                # append cn to san_list
                self.logger.debug("EABhandler._csr_check(): append cn to san_list")
                san_list.append(cn_)

        self.logger.debug("EABhandler._cn_add() ended")
        return san_list

    def _list_regex_check(self, entry: str, list_: List[str]) -> bool:
        """Check entry against regex"""
        self.logger.debug("EABhandler._list_regex_check()")

        check_result = False
        for regex in list_:
            if regex.startswith("*."):
                regex = regex.replace("*.", ".")
            regex_compiled = re.compile(regex)
            if bool(regex_compiled.search(entry)):
                # parameter is in set flag accordingly and stop loop
                check_result = True

        self.logger.debug(
            "EABhandler._list_regex_check() ended with: {0}".format(check_result)
        )
        return check_result

    def _wllist_check(self, entry: str, list_: List[str], toggle: bool = False) -> bool:
        """Check string against list"""
        self.logger.debug("EABhandler._wllist_check({0}:{1})".format(entry, toggle))
        self.logger.debug("check against list: {0}".format(list_))

        # default setting
        check_result = False

        if entry:
            if list_:
                check_result = self._list_regex_check(entry, list_)
            else:
                # empty list, flip parameter to make the check successful
                check_result = True

        if toggle:
            # toggle result if this is a blocked_domainlist
            check_result = not check_result

        self.logger.debug(
            "EABhandler._wllist_check() ended with: {0}".format(check_result)
        )
        return check_result

    def _allowed_domains_check(self, csr: str, domain_list: List[str]) -> str:
        """Check allowed domains"""
        self.logger.debug("EABhandler.allowed_domains_check()")

        (san_list, check_list) = self._chk_san_lists_get(csr)
        (san_list) = self._cn_add(csr, san_list)

        # go over the san list and check each entry
        for san in san_list:
            check_list.append(self._wllist_check(san, domain_list))

        if check_list:
            # cover a cornercase with empty checklist (no san, no cn)
            if False in check_list:
                result = "Either CN or SANs are not allowed by profile"
            else:
                result = False

        self.logger.debug("EABhandler.allowed_domains_check() ended with: %s", result)
        return result

    def eab_kid_get(self, csr: str, revocation=False) -> str:
        """Get eab kid from database based on csr"""
        self.logger.debug("EABhandler.eab_kid_get()")

        try:
            # look up eab_kid from database based on csr
            from acme_srv.db_handler import DBstore  # pylint: disable=c0415

            if revocation:
                # this is a lookup for a revocation request
                search_key = "cert_raw"
            else:
                # this is a lookup for an enrollment request
                search_key = "csr"

            dbstore = DBstore(False, self.logger)
            result_dic = dbstore.certificate_lookup(
                search_key,
                csr,
                vlist=[
                    "name",
                    "order__name",
                    "order__account__name",
                    "order__account__eab_kid",
                ],
            )
            if result_dic and "order__account__eab_kid" in result_dic:
                eab_kid = result_dic["order__account__eab_kid"]
            else:
                eab_kid = None

        except Exception as err:
            self.logger.error("Database error while retrieving eab_kid: %s", err)
            eab_kid = None

        self.logger.debug("EABhandler.eab_kid_get() ended with: %s", eab_kid)
        return eab_kid

    def eab_profile_get(self, csr: str, revocation=False) -> str:
        """Get eab profile"""
        self.logger.debug("EABhandler._eab_profile_get()")

        # load profiles from eab credentials database
        profiles_dic = self.key_file_load()

        # get eab_kid from database
        eab_kid = self.eab_kid_get(csr, revocation=revocation)

        # get profile from profiles_dic
        if (
            profiles_dic
            and eab_kid
            and eab_kid in profiles_dic
            and "cahandler" in profiles_dic[eab_kid]
        ):
            profile_dic = profiles_dic[eab_kid]["cahandler"]
        else:
            profile_dic = {}

        self.logger.debug(
            "EABhandler._eab_profile_get() ended with: %s", bool(profile_dic)
        )
        return profile_dic

    def key_file_load(self) -> Dict[str, str]:
        """Load profiles from eab credentials database"""
        self.logger.debug("EABhandler.key_file_load()")

        if self.db_host and self.db_name and self.db_user and self.db_password:
            data_dic = {}

            # query all active (status = 1) profiles for configured eab account
            SQL_QUERY = "SELECT key_id, profile FROM credentials WHERE STATUS = 1;"

            if self.db_system == "mssql":
                try:
                    # create sql server connection string
                    conn_str = (
                        "Server="
                        + self.db_host
                        + ";Database="
                        + self.db_name
                        + ";Encrypt=yes;UID="
                        + self.db_user
                        + ";PWD="
                        + self.db_password
                        + ";TrustServerCertificate=yes"
                    )
                    conn = connect(conn_str)

                    cursor = conn.cursor()
                    cursor.execute(SQL_QUERY)

                    # forms data_dic object with the same structure as in kid_profile_handler
                    rows = cursor.fetchall()
                    for row in rows:
                        data_dic[row.key_id] = row.profile

                    conn.close()

                except Exception as err:
                    self.logger.error("EABhandler.key_file_load() error: %s", err)

            elif self.db_system == "postgres":
                try:
                    conn = psycopg2.connect(
                        host=self.db_host,
                        dbname=self.db_name,
                        user=self.db_user,
                        password=self.db_password,
                    )

                    cursor = conn.cursor()
                    cursor.execute(SQL_QUERY)

                    # forms data_dic object with the same structure as in kid_profile_handler
                    rows = cursor.fetchall()
                    for row in rows:
                        data_dic[str(row[0])] = str(row[1])

                    conn.close()

                except Exception as err:
                    self.logger.error("EABhandler.key_file_load() error: %s", err)

        self.logger.debug("EABhandler.key_file.load() ended: {%s}", bool(data_dic))
        return data_dic

    def mac_key_get(self, key_id: str) -> Optional[str]:
        """Check external account binding"""
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
