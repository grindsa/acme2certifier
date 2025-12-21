# -*- coding: utf-8 -*-
"""Directory class"""
# pylint: disable=e0401, r0913, r1705

from __future__ import print_function
import uuid
import json
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass, field
from .version import __version__, __dbversion__
from .helper import (
    load_config,
    ca_handler_load,
    config_profile_load,
    config_async_mode_load,
)
from .db_handler import DBstore

GH_HOME = "https://github.com/grindsa/acme2certifier"


@dataclass
class DirectoryConfig:
    """Configuration dataclass for Directory settings and parameters."""

    supress_version: bool = False
    db_check: bool = False
    suppress_product_information: bool = False
    tos_url: Optional[str] = None
    url_prefix: str = ""
    home: str = GH_HOME
    caaidentities: List[str] = field(default_factory=list)
    profiles: Dict = field(default_factory=dict)
    eab: bool = False
    acme_url: Optional[str] = None
    profiles_sync: bool = False
    profiles_sync_interval: int = 604800  # default: 7 days
    async_mode: bool = False


class DirectoryRepository:
    """Repository for all Directory-related database access."""

    def __init__(self, dbstore: object, logger: object) -> None:
        """Initialize DirectoryRepository with dbstore and logger."""
        self.dbstore = dbstore
        self.logger = logger

    def get_db_version(self) -> Tuple[Optional[str], Optional[str]]:
        """Get the current database version from the DBstore."""
        try:
            return self.dbstore.dbversion_get()
        except Exception as err:
            self.logger.critical(
                "Database error: failed to check database version: %s", err
            )
            return None, None

    def profile_list_get(self) -> List[Dict[str, object]]:
        """Get the list of profiles from the database."""
        try:
            profiles = self.dbstore.hkparameter_get("profiles")
        except Exception as err:
            self.logger.critical("Database error: failed to get profile list: %s", err)
            profiles = []
        if profiles:
            try:
                return json.loads(profiles)
            except Exception as err_:
                self.logger.error(
                    "Error when loading the profiles parameter from database: %s", err_
                )
                return []

    def profile_list_set(self, data_dic: Dict[str, object]) -> None:
        """Set the list of profiles in the database."""
        try:
            self.dbstore.hkparameter_add(data_dic)
        except Exception as err:
            self.logger.critical("Database error: failed to set profile list: %s", err)


class Directory:
    """Main handler for ACME Directory logic, configuration, and response building."""

    def __init__(
        self,
        debug: Optional[object] = None,
        srv_name: Optional[str] = None,
        logger: Optional[object] = None,
    ) -> None:
        """Initialize Directory with configuration, repository, and logger."""
        self.server_name = srv_name
        self.logger = logger
        self.dbstore = DBstore(debug, self.logger)
        self.repository = DirectoryRepository(self.dbstore, self.logger)
        self.config = DirectoryConfig()
        self.cahandler = None
        self.version = __version__
        self.dbversion = __dbversion__

    def __enter__(self) -> "Directory":
        """Enter context manager for Directory."""
        self._load_configuration()
        return self

    def __exit__(self, *args) -> None:
        """Exit context manager for Directory."""
        # pylint: disable=w0107
        pass

    def _load_configuration(self) -> None:
        """Load and parse all Directory configuration from file and environment."""
        self.logger.debug("Directory._load_configuration()")
        config_dic = load_config(self.logger, "Directory")

        self._parse_directory_section(config_dic)
        self._parse_booleans(config_dic)
        self._parse_eab_and_profiles(config_dic)
        self._parse_cahandler_section(config_dic)
        self._load_ca_handler(config_dic)
        self.config.async_mode = config_async_mode_load(
            self.logger, config_dic, self.dbstore.type
        )
        self.logger.debug("Directory._load_configuration() ended")

    def _parse_directory_section(self, config_dic: object) -> None:
        """Parse the [Directory] section for basic config values."""
        if "Directory" in config_dic:
            cfg_dic = dict(config_dic["Directory"])
            self.config.tos_url = cfg_dic.get("tos_url", None)
            self.config.url_prefix = cfg_dic.get("url_prefix", "")
            self.config.home = cfg_dic.get("home", GH_HOME)
            tmp_caaidentities = config_dic.get(
                "Directory", "caaidentities", fallback=None
            )
            if tmp_caaidentities:
                self.config.caaidentities = self._parse_caaidentities(tmp_caaidentities)

    def _parse_caaidentities(self, value: str) -> List[str]:
        """Parse the caaIdentities config value as JSON or fallback to list."""
        try:
            return json.loads(value)
        except Exception as err_:
            if "[" not in value and '"' not in value:
                return [value]
            else:
                self.logger.error(
                    "Error when loading the caaIdentities parameter from config: %s",
                    err_,
                )
                return []

    def _parse_booleans(self, config_dic: object) -> None:
        """Parse boolean config values for Directory settings."""
        for key, attr in [
            ("supress_version", "supress_version"),
            ("db_check", "db_check"),
            ("suppress_product_information", "suppress_product_information"),
        ]:
            try:
                setattr(
                    self.config,
                    attr,
                    config_dic.getboolean(
                        "Directory", key, fallback=getattr(self.config, attr)
                    ),
                )
            except Exception as err_:
                self.logger.error("%s not set: %s", key, err_)

    def _parse_eab_and_profiles(self, config_dic: object) -> None:
        """Parse EAB handler and profile configuration."""
        if (
            "EABhandler" in config_dic
            and "eab_handler_file" in config_dic["EABhandler"]
        ):
            self.config.eab = True
        self.config.profiles = config_profile_load(self.logger, config_dic)

    def _parse_cahandler_section(self, config_dic: object) -> None:
        """Parse the [CAHandler] section for ACME URL and profile sync settings."""
        self.logger.debug("Directory._parse_cahandler_section()")
        if "CAhandler" in config_dic:
            cfg_dic = dict(config_dic["CAhandler"])
            self.config.acme_url = cfg_dic.get("acme_url", None)
            try:
                self.config.profiles_sync = config_dic.getboolean(
                    "CAhandler",
                    "profiles_sync",
                    fallback=self.config.profiles_sync,
                )
            except Exception as err_:
                self.logger.error("profiles_sync not set: %s", err_)

            if self.config.profiles_sync:
                if self.config.profiles:
                    self.logger.error(
                        "Profiles are configured via acme_srv.cfg. Disabling profile sync."
                    )
                    self.config.profiles_sync = False

                if not self.config.acme_url:
                    self.logger.error(
                        "profiles_sync is set but no acme_url configured."
                    )
                    self.config.profiles_sync = False
            if self.config.profiles_sync:
                try:
                    self.config.profiles_sync_interval = config_dic.getint(
                        "CAhandler",
                        "profiles_sync_interval",
                        fallback=self.config.profiles_sync_interval,
                    )
                except Exception as err_:
                    self.logger.error("profiles_sync_interval not set: %s", err_)
                self.logger.debug(
                    "Directory._parse_cahandler_section(): profiles_sync is enabled. Interval: %s seconds",
                    self.config.profiles_sync_interval,
                )
        self.logger.debug("Directory._parse_cahandler_section() ended")

    def _load_ca_handler(self, config_dic: object) -> None:
        """Load the CA handler module as configured."""
        ca_handler_module = ca_handler_load(self.logger, config_dic)
        if ca_handler_module:
            self.cahandler = ca_handler_module.CAhandler
        else:
            self.logger.critical("No ca_handler loaded")

    def _build_meta_information(self) -> Dict[str, object]:
        """Build the meta information dictionary for the directory response."""
        self.logger.debug("Directory._build_meta_information()")
        meta_dic = {}
        if not self.config.suppress_product_information:
            meta_dic = {
                "home": self.config.home,
                "author": "grindsa <grindelsack@gmail.com>",
                "name": "acme2certifier",
            }
            if not self.config.supress_version:
                meta_dic["version"] = self.version
        else:
            if self.config.home != GH_HOME:
                meta_dic["home"] = self.config.home
        if self.config.tos_url:
            meta_dic["termsOfService"] = self.config.tos_url
        if self.config.caaidentities:
            meta_dic["caaIdentities"] = self.config.caaidentities
        if self.config.profiles:
            meta_dic["profiles"] = self.config.profiles
        if self.config.eab:
            meta_dic["externalAccountRequired"] = True
        self.logger.debug("Directory._build_meta_information() ended")
        return meta_dic

    def _build_directory_response(self) -> Dict[str, object]:
        """Build the full directory response dictionary for the ACME directory endpoint."""
        self.logger.debug("Directory._build_directory_response()")
        d_dic = {
            "newAuthz": self.server_name + self.config.url_prefix + "/acme/new-authz",
            "newNonce": self.server_name + self.config.url_prefix + "/acme/newnonce",
            "newAccount": self.server_name
            + self.config.url_prefix
            + "/acme/newaccount",
            "newOrder": self.server_name + self.config.url_prefix + "/acme/neworders",
            "revokeCert": self.server_name
            + self.config.url_prefix
            + "/acme/revokecert",
            "keyChange": self.server_name + self.config.url_prefix + "/acme/key-change",
            "renewalInfo": self.server_name
            + self.config.url_prefix
            + "/acme/renewal-info",
            "meta": self._build_meta_information(),
        }
        if self.config.db_check:
            version, _script_name = self.repository.get_db_version()
            if version == self.dbversion:
                d_dic["meta"]["db_check"] = "OK"
            else:
                self.logger.error(
                    "Database schema mismatch detected: detected: %s/ expected: %s",
                    version,
                    self.dbversion,
                )
                d_dic["meta"]["db_check"] = "NOK"
        # generate random key in json as recommended by LE
        d_dic[
            uuid.uuid4().hex
        ] = "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417"
        self.logger.debug("Directory._build_directory_response() ended")
        return d_dic

    def get_directory_response(self) -> Dict[str, object]:
        """Public method to get the ACME directory response, including CA handler checks."""
        self.logger.debug("Directory.get_directory_response()")
        error = None

        if self.cahandler:

            with self.cahandler(None, self.logger) as ca_handler:
                if hasattr(ca_handler, "handler_check"):
                    error = ca_handler.handler_check()
                if (
                    self.config.profiles_sync
                    and hasattr(ca_handler, "load_profiles")
                    and not error
                ):
                    self.config.profiles = ca_handler.load_profiles(
                        self.repository,
                        self.config.acme_url,
                        self.config.profiles_sync_interval,
                        self.config.async_mode,
                    )

        else:
            error = "No handler loaded"

        if not error:
            d_dic = self._build_directory_response()
        else:
            self.logger.critical(
                "CA handler error during get_directory_response: %s", error
            )
            d_dic = {"error": "error in ca_handler configuration"}
        return d_dic

    def directory_get(self) -> Dict[str, object]:
        """return response to ACME directory call"""
        self.logger.debug("Directory.directory_get()")
        return self.get_directory_response()

    def servername_get(self) -> str:
        """dumb function to return servername"""
        self.logger.debug("Directory.servername_get()")
        return self.server_name
