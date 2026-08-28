# -*- coding: utf-8 -*-
"""Configuration utilities for acme2certifier"""

import configparser
import json
import logging
import os
import warnings
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

from .plugin_loader import eab_handler_load
from .global_variables import CONFIGURATION_ERROR_DETAIL, PARSING_ERR_MSG
from .security_gate import SECURITY_DISABLE_ACK_ENV, security_disable_acknowledged

# Emit acme_srv.cfg path deprecation warnings at most once per path per process.
_ACME_SRV_CFG_PATH_WARNED: Set[str] = set()
# Emit successful load INFO at most once per absolute path per process.
_ACME_SRV_CFG_LOADED: Set[str] = set()
# Last successful load (path, source, format); used after logger_setup.
_LAST_LOADED_CFG: Optional[Tuple[str, str, str]] = None
ACME_SRV_CFG_FILENAME = "acme_srv.cfg"
ACME_SRV_YAML_FILENAMES = ("acme_srv.yaml", "acme_srv.yml")
_YAML_CONFIG_EXTENSIONS = {".yaml", ".yml"}


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys."""

    def construct_mapping(
        self, node: yaml.nodes.MappingNode, deep: bool = False
    ) -> Dict[Any, Any]:
        if not isinstance(node, yaml.nodes.MappingNode):
            return super().construct_mapping(node, deep=deep)
        self.flatten_mapping(node)
        mapping: Dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in mapping:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _log_cfg_loaded_once(
    logger: logging.Logger, cfg_path: str, source: str, cfg_format: str
) -> None:
    """Log successful acme_srv.cfg load once per absolute path (then DEBUG)."""
    abs_path = os.path.abspath(cfg_path)
    message = "Loaded acme_srv.cfg %s (%s, %s)"
    if abs_path not in _ACME_SRV_CFG_LOADED:
        _ACME_SRV_CFG_LOADED.add(abs_path)
        logger.info(message, abs_path, source, cfg_format)
    else:
        logger.debug(message, abs_path, source, cfg_format)


def log_loaded_acme_srv_cfg(logger: logging.Logger) -> None:
    """Emit Loaded acme_srv.cfg once. Call after ``logger_setup``.

    Early ``load_config()`` calls (no logger) happen before logging is
    configured; this flushes the pending path/source to the app logger.
    """
    if _LAST_LOADED_CFG:
        path, source, cfg_format = _LAST_LOADED_CFG
        _log_cfg_loaded_once(logger, path, source, cfg_format)


def config_check(logger: logging.Logger, config_dic: Dict):
    """check configuration"""
    logger.debug("Helper.config_check()")

    for section, section_dic in config_dic.items():
        for key, value in section_dic.items():
            if value.startswith('"') or value.endswith('"'):
                logger.warning(
                    'Section %s option: %s contains " characters. Please check if this is required!',
                    section,
                    key,
                )


def config_profile_load(logger: logging.Logger, config_dic: Dict[str, str]):
    """load parameters"""
    logger.debug("Helper.config_profile_load()")

    # load profiles
    profiles = {}
    if "Order" in config_dic and "profiles" in config_dic["Order"]:
        try:
            profiles = json.loads(config_dic["Order"]["profiles"])
        except Exception as err_:
            logger.warning("Failed to load profiles from configuration: %s", err_)

    logger.debug("Helper.config_profile_load() ended")
    return profiles


def config_eab_profile_load(logger: logging.Logger, config_dic: Dict[str, str]):
    """load parameters"""
    logger.debug("Helper.config_eab_profile_load()")

    eab_profiling = False
    eab_handler = None

    try:
        # load eab_profiling from eabhandler section
        eab_profiling = config_dic.getboolean(
            "EABhandler", "eab_profiling", fallback=False
        )
    except Exception as err:
        logger.error("Failed to load eabprofile from configuration: %s", err)
        eab_profiling = False

    if (
        not eab_profiling
        and "CAhandler" in config_dic
        and "eab_profiling" in config_dic["CAhandler"]
    ):
        # load eab_profiling from CAHandler section - deprecated
        logger.warning(
            "eab_profiling found in CAhandler section - this is deprecated, please use EABhandler section"
        )
        try:
            eab_profiling = config_dic.getboolean(
                "CAhandler", "eab_profiling", fallback=False
            )
        except Exception as err:
            logger.error("Failed to load eabprofile from configuration: %s", err)
            eab_profiling = False

    if eab_profiling:
        if "EABhandler" in config_dic and (
            "eab_handler_file" in config_dic["EABhandler"]
            or "eab_handler_module" in config_dic["EABhandler"]
        ):
            # load eab_handler according to configuration
            eab_handler_module = eab_handler_load(logger, config_dic)
            if not eab_handler_module:
                logger.critical("EABHandler could not get loaded")
            else:
                eab_handler = eab_handler_module.EABhandler
        else:
            logger.critical("%s: EABHandler incomplete", CONFIGURATION_ERROR_DETAIL)

    logger.debug("_config_profile_load() ended")
    return eab_profiling, eab_handler


def config_headerinfo_load(logger: logging.Logger, config_dic: Dict[str, str]):
    """load parameters"""
    logger.debug("Helper.config_headerinfo_load()")

    header_info_field = None
    if (
        "Order" in config_dic
        and "header_info_list" in config_dic["Order"]
        and config_dic["Order"]["header_info_list"]
    ):
        try:
            header_info_field = json.loads(config_dic["Order"]["header_info_list"])[0]
        except Exception as err_:
            logger.warning(
                "Failed to parse header_info_list from configuration: %s", err_
            )
    #
    logger.debug("Helper.config_headerinfo_load() ended")
    return header_info_field


def config_allowed_header_values_load(logger: logging.Logger, config_dic) -> List[str]:
    """Load [Order] allowed_header_values JSON list from config."""
    logger.debug("Helper.config_allowed_header_values_load()")
    result: List[str] = []
    if (
        "Order" not in config_dic
        or "allowed_header_values" not in config_dic["Order"]
        or not config_dic["Order"]["allowed_header_values"]
    ):
        logger.debug("Helper.config_allowed_header_values_load() ended with 0 entries")
        return result

    try:
        loaded = json.loads(config_dic.get("Order", "allowed_header_values"))
        if not isinstance(loaded, list):
            raise ValueError("allowed_header_values must be a JSON list")
        result = [str(item) for item in loaded]
    except Exception as err_:
        logger.warning(
            "Failed to parse allowed_header_values from configuration: %s. "
            "Treating as empty allowlist.",
            err_,
        )
        result = []

    logger.debug(
        "Helper.config_allowed_header_values_load() ended with %s entries",
        len(result),
    )
    return result


def header_value_allowlist_resolve(logger: logging.Logger, cahandler) -> List[str]:
    """Resolve header-value allowlist for client-selected enrollment parameters.

    Prefer ``[Order] allowed_header_values``. Fall back to handler
    ``allowed_templates`` (MS compatibility alias).
    """
    logger.debug("Helper.header_value_allowlist_resolve()")
    config_dic = load_config(logger)
    order_values = config_allowed_header_values_load(logger, config_dic)
    if order_values:
        logger.debug(
            "Helper.header_value_allowlist_resolve() ended with Order list (%s)",
            len(order_values),
        )
        return order_values

    templates = getattr(cahandler, "allowed_templates", None) or []
    if templates:
        result = [str(item) for item in templates]
        logger.debug(
            "Helper.header_value_allowlist_resolve() ended with allowed_templates "
            "fallback (%s)",
            len(result),
        )
        return result

    logger.debug("Helper.header_value_allowlist_resolve() ended with empty list")
    return []


def config_enroll_config_log_load(logger: logging.Logger, config_dic: Dict[str, str]):
    """load parameters"""
    logger.debug("Helper.config_enroll_config_log_load()")

    enrollment_cfg_log = False
    enrollment_cfg_log_skip_list = []

    if "CAhandler" in config_dic:
        try:
            enrollment_cfg_log = config_dic.getboolean(
                "CAhandler", "enrollment_config_log", fallback=False
            )
        except Exception as err_:
            logger.warning(
                "Failed to load enrollment_config_log from configuration: %s", err_
            )

        if "enrollment_config_log_skip_list" in config_dic["CAhandler"]:
            try:
                enrollment_cfg_log_skip_list = json.loads(
                    config_dic["CAhandler"]["enrollment_config_log_skip_list"]
                )
            except Exception as err_:
                logger.warning(
                    "Failed to parse enrollment_config_log_skip_list from configuration: %s",
                    err_,
                )
                enrollment_cfg_log_skip_list = PARSING_ERR_MSG

    logger.debug(
        "Helper.config_enroll_config_log_load() ended with: %s", enrollment_cfg_log
    )
    return enrollment_cfg_log, enrollment_cfg_log_skip_list


def config_dns_server_list_load(
    logger: logging.Logger, config_dic: Dict[str, str]
) -> Tuple[List[str], int]:
    """load parameters"""
    logger.debug("Helper.config_dns_server_list_load()")

    dns_server_list = []
    dns_validation_pause_timer = 0.5

    if "DEFAULT" in config_dic and "dns_server_list" in config_dic["DEFAULT"]:
        try:
            dns_server_list = json.loads(config_dic["DEFAULT"]["dns_server_list"])
        except Exception as err_:
            logger.warning(
                "Failed to load dns_server_list from configuration: %s", err_
            )
    elif "Challenge" in config_dic and "dns_server_list" in config_dic["Challenge"]:
        logger.warning(
            "dns_server_list parameter found in Challenge section - this is deprecated, please use DEFAULT section"
        )
        try:
            dns_server_list = json.loads(config_dic["Challenge"]["dns_server_list"])
        except Exception as err_:
            logger.warning(
                "Failed to load dns_server_list from configuration: %s", err_
            )

        if (
            "Challenge" in config_dic
            and "dns_validation_pause_timer" in config_dic["Challenge"]
        ):
            try:
                dns_validation_pause_timer = int(
                    config_dic["Challenge"]["dns_validation_pause_timer"]
                )
            except Exception as err_:
                logger.warning(
                    "Failed to parse dns_validation_pause_timer from configuration: %s",
                    err_,
                )

    logger.debug("Helper.config_dns_server_list_load() ended with: %s", dns_server_list)
    return dns_server_list, dns_validation_pause_timer


def config_allowed_domainlist_load(logger: logging.Logger, config_dic: Dict[str, str]):
    """load parameters"""
    logger.debug("Helper.config_allowed_domainlist_load()")

    allowed_domainlist = []

    if "Order" in config_dic and "allowed_domainlist" in config_dic["Order"]:
        try:
            allowed_domainlist = json.loads(config_dic["Order"]["allowed_domainlist"])
        except Exception as err_:
            logger.warning(
                "Failed to load allowed_domainlist from configuration: %s", err_
            )
            allowed_domainlist = PARSING_ERR_MSG

    if (
        not allowed_domainlist
        and "CAhandler" in config_dic
        and "allowed_domainlist" in config_dic["CAhandler"]
    ):
        logger.warning(
            "allowed_domainlist parameter found in CAhandler section - this is deprecated, please use Order section"
        )
        try:
            allowed_domainlist = json.loads(
                config_dic["CAhandler"]["allowed_domainlist"]
            )
        except Exception as err_:
            logger.warning(
                "Failed to load allowed_domainlist from configuration: %s", err_
            )
            allowed_domainlist = PARSING_ERR_MSG

    logger.debug(
        "Helper.config_allowed_domainlist_load() ended with: %s", allowed_domainlist
    )
    return allowed_domainlist


def config_allowed_iplist_load(logger: logging.Logger, config_dic: Dict[str, str]):
    """load parameters"""
    logger.debug("Helper.config_allowed_iplist_load()")

    allowed_iplist = []

    if "Order" in config_dic and "allowed_iplist" in config_dic["Order"]:
        try:
            allowed_iplist = json.loads(config_dic["Order"]["allowed_iplist"])
        except Exception as err_:
            logger.warning("Failed to load allowed_iplist from configuration: %s", err_)
            allowed_iplist = PARSING_ERR_MSG

    logger.debug("Helper.config_allowed_iplist_load() ended with: %s", allowed_iplist)
    return allowed_iplist


def config_async_mode_load(
    logger: logging.Logger, config_dic: Dict[str, str], db_type: str
):
    """load parameters"""
    logger.debug("Helper.config_async_mode_load()")

    async_mode = False

    async_cfg = config_dic.getboolean("DEFAULT", "async_mode", fallback=False)
    if async_cfg:
        if db_type == "django":
            async_mode = True
        else:
            logger.info(
                "asynchronous Challenge validation disabled, requires django db handler"
            )
    logger.debug("Helper.config_async_mode_load() ended with: %s", async_mode)
    return async_mode


def legacy_acme_get_load(logger: logging.Logger, config_dic) -> bool:
    """Load ``legacy_acme_get`` from ``[DEFAULT]`` (default False).

    When False (default), unauthenticated GET on challenge and authorization
    resources is rejected with HTTP 405 (RFC 8555 / Let's Encrypt behavior).
    When True, legacy unauthenticated GET is allowed.
    """
    logger.debug("Helper.legacy_acme_get_load()")
    enabled = False
    if config_dic:
        enabled = config_dic.getboolean("DEFAULT", "legacy_acme_get", fallback=False)
    if enabled:
        logger.warning(
            "legacy_acme_get is enabled: unauthenticated GET is allowed for "
            "challenge and authorization resources (RFC 8555 prefers POST-as-GET)."
        )
    logger.debug("Helper.legacy_acme_get_load() ended with: %s", enabled)
    return enabled


def challenge_type_configuration_validate(logger: logging.Logger, config_dic) -> None:
    """Emit a startup warning when all RFC 8555 challenge types are disabled."""
    logger.debug("Helper.challenge_type_configuration_validate()")
    if not config_dic:
        return

    std_enabled = any(
        [
            config_dic.getboolean("Challenge", "http_01_support", fallback=True),
            config_dic.getboolean("Challenge", "dns_01_support", fallback=True),
            config_dic.getboolean("Challenge", "tls_alpn_01_support", fallback=True),
        ]
    )
    opt_enabled = config_dic.getboolean(
        "Challenge", "dns_persist_01_support", fallback=False
    )
    if std_enabled or opt_enabled:
        return

    logger.warning(
        "All RFC 8555 challenge types are disabled and dns_persist_01_support "
        "is off; new authorizations will have no challenges unless identifiers "
        "are prevalidated or challenge validation is disabled "
        "(globally, via EAB profile, or with forward/reverse address checks)."
    )


def tnauthlist_configuration_validate(logger: logging.Logger, config_dic) -> None:
    """Emit a startup message when ``tnauthlist_support`` is enabled.

    tkauth-01 has no authority token verification, so the challenge is refused
    unless the break-glass env var acknowledges the risk.
    """
    logger.debug("Helper.tnauthlist_configuration_validate()")
    if not config_dic:
        return
    if not config_dic.getboolean("Order", "tnauthlist_support", fallback=False):
        return

    if security_disable_acknowledged():
        logger.critical(
            "**** SECURITY DISABLE ACKNOWLEDGED via %s: tkauth-01 challenges are "
            "accepted without verifying the authority token. Any account can obtain "
            "certificates for telephone number ranges it does not hold. ****",
            SECURITY_DISABLE_ACK_ENV,
        )
    else:
        logger.error(
            "tnauthlist_support is enabled but tkauth-01 validation is not "
            "implemented; TNAuthList authorizations will be marked invalid and "
            "enrollment will fail. Set %s=1 to accept unverified authority tokens "
            "for testing purposes only.",
            SECURITY_DISABLE_ACK_ENV,
        )


def acme_get_method_not_allowed_problem() -> Dict[str, Any]:
    """ACME problem document for rejected plain GET on challenge/authz."""
    return {
        "type": "urn:ietf:params:acme:error:malformed",
        "detail": "Method not allowed. Use POST-as-GET.",
        "status": 405,
    }


def config_proxy_load(logger, config_dic: Dict[str, str], host_name: str):
    """load parameters"""
    logger.debug("_config_proxy_load()")

    # Lazy import to avoid circular dependency
    from .network import parse_url, proxy_check  # pylint: disable=C0415

    proxy = {}
    if "DEFAULT" in config_dic and "proxy_server_list" in config_dic["DEFAULT"]:
        try:
            proxy_list = json.loads(config_dic["DEFAULT"]["proxy_server_list"])
            url_dic = parse_url(logger, host_name)
            if "host" in url_dic:
                # check if we need to set the proxy
                fqdn, _port = url_dic["host"].split(":")
                proxy_server = proxy_check(logger, fqdn, proxy_list)
                proxy = {"http": proxy_server, "https": proxy_server}
        except Exception as err_:
            logger.warning(
                "Failed to parse proxy_server_list from configuration: %s",
                err_,
            )

    logger.debug("config_proxy_load() ended with: %s", proxy)
    return proxy


def _warn_acme_srv_cfg_path(
    path: str,
    preferred: str,
    logger: logging.Logger,
) -> None:
    """Warn once when a non-preferred acme_srv.cfg path is used."""
    if path in _ACME_SRV_CFG_PATH_WARNED:
        return
    _ACME_SRV_CFG_PATH_WARNED.add(path)
    message = (
        f"Loading acme_srv.cfg from {path}; prefer {preferred} "
        "or set ACME_SRV_CONFIGFILE. "
        "This fallback path will change in acme2certifier 0.48."
    )
    warnings.warn(message, DeprecationWarning, stacklevel=4)
    logger.warning(message)


def default_deploy_base_dir() -> str:
    """Resolve pip/DEB/RPM deploy root for writable runtime files.

    Order:
    1. ``ACME2CERTIFIER_BASE_DIR`` when set
    2. ``/var/www/acme2certifier`` if that directory exists (DEB / Ubuntu pip)
    3. ``/opt/acme2certifier`` if that directory exists (RPM)
    4. ``/var/www/acme2certifier`` as the default install layout
    """
    env_base = os.environ.get("ACME2CERTIFIER_BASE_DIR")
    if env_base:
        return env_base
    for candidate in ("/var/www/acme2certifier", "/opt/acme2certifier"):
        if os.path.isdir(candidate):
            return candidate
    return "/var/www/acme2certifier"


def default_wsgi_dbfile() -> str:
    """Default SQLite path when ``DBhandler.dbfile`` is unset."""
    return os.path.join(default_deploy_base_dir(), "acme_srv.db")


def resolve_config_path(path: Optional[str]) -> Optional[str]:
    """Resolve relative config paths against ``ACME2CERTIFIER_BASE_DIR``.

    Absolute paths are unchanged. Relative paths without ``ACME2CERTIFIER_BASE_DIR``
    stay relative (process CWD), matching openssl CA handler behavior.
    """
    if not path:
        return path
    if os.path.isabs(path):
        return path
    base_dir = os.environ.get("ACME2CERTIFIER_BASE_DIR")
    if not base_dir:
        return path
    return os.path.normpath(os.path.join(base_dir, path))


def _acme_srv_config_paths(directory: str) -> Tuple[str, ...]:
    """Return cfg, then yaml, then yml paths for one directory."""
    names = (ACME_SRV_CFG_FILENAME,) + ACME_SRV_YAML_FILENAMES
    return tuple(os.path.join(directory, name) for name in names)


def _first_existing_acme_srv_config(directory: str) -> Optional[str]:
    """First existing acme_srv config in a directory (``.cfg`` wins)."""
    for path in _acme_srv_config_paths(directory):
        if os.path.isfile(path):
            return path
    return None


def _default_acme_srv_cfg_file(
    logger: Optional[logging.Logger] = None,
) -> str:
    """Resolve default acme_srv.cfg after the package move.

    Candidates (first existing file wins). At each location ``acme_srv.cfg``
    is tried before ``acme_srv.yaml`` then ``acme_srv.yml``:

    1. Preferred OS deploy roots: ``/var/www/acme2certifier/`` (DEB) or
       ``/opt/acme2certifier/`` (RPM)
    2. Checkout / install root: ``<repo>/``
    3. Nested deploy paths under ``.../acme_srv/`` (warn)
    4. Next to the package module: ``.../acme_srv/``
    5. Legacy repo layout: ``<repo>/acme_srv/`` (warn)

    If nothing exists, fall back to ``/var/www/acme2certifier/acme_srv.cfg``.
    """
    log = logger or logging.getLogger(__name__)
    log.debug("Helper._default_acme_srv_cfg_file() start")

    helpers_dir = os.path.dirname(os.path.abspath(__file__))
    pkg_dir = os.path.dirname(helpers_dir)  # .../acme_srv (new or install tree)
    install_or_repo_root = os.path.dirname(os.path.dirname(pkg_dir))
    fallback_cfg = os.path.join("/var/www/acme2certifier", ACME_SRV_CFG_FILENAME)

    preferred_dirs = (
        "/var/www/acme2certifier",
        "/opt/acme2certifier",
        install_or_repo_root,
    )
    nested_dirs = (
        ("/var/www/acme2certifier/acme_srv", "/var/www/acme2certifier"),
        ("/opt/acme2certifier/acme_srv", "/opt/acme2certifier"),
    )
    legacy_dir = os.path.join(install_or_repo_root, "acme_srv")
    log.debug(
        "Helper._default_acme_srv_cfg_file(): candidates preferred=%s "
        "nested=%s packaged=%s legacy=%s",
        [path for d in preferred_dirs for path in _acme_srv_config_paths(d)],
        [path for d, _ in nested_dirs for path in _acme_srv_config_paths(d)],
        _acme_srv_config_paths(pkg_dir),
        _acme_srv_config_paths(legacy_dir),
    )

    for deploy_dir in preferred_dirs:
        found = _first_existing_acme_srv_config(deploy_dir)
        if found:
            log.debug(
                "Helper._default_acme_srv_cfg_file() ended with preferred %s",
                found,
            )
            return found

    for nested_dir, preferred_dir in nested_dirs:
        found = _first_existing_acme_srv_config(nested_dir)
        if found:
            preferred = os.path.join(preferred_dir, os.path.basename(found))
            _warn_acme_srv_cfg_path(found, preferred, log)
            log.debug(
                "Helper._default_acme_srv_cfg_file() ended with nested %s",
                found,
            )
            return found

    packaged = _first_existing_acme_srv_config(pkg_dir)
    if packaged:
        log.debug(
            "Helper._default_acme_srv_cfg_file() ended with packaged %s",
            packaged,
        )
        return packaged

    legacy = _first_existing_acme_srv_config(legacy_dir)
    if legacy:
        preferred = os.path.join(install_or_repo_root, os.path.basename(legacy))
        _warn_acme_srv_cfg_path(legacy, preferred, log)
        log.debug(
            "Helper._default_acme_srv_cfg_file() ended with legacy %s",
            legacy,
        )
        return legacy

    log.debug(
        "Helper._default_acme_srv_cfg_file() ended with fallback %s",
        fallback_cfg,
    )
    return fallback_cfg


def _new_config_parser() -> configparser.ConfigParser:
    """Return an empty ConfigParser matching historical load_config() settings."""
    config = configparser.ConfigParser(interpolation=None)
    config.optionxform = str
    return config


def _read_config_file(path: str) -> str:
    """Read a config file as UTF-8. ``utf-8-sig`` strips a leading BOM."""
    with open(path, encoding="utf-8-sig") as handle:
        return handle.read()


def _detect_config_format(content: str, path: str) -> str:
    """Detect INI vs YAML from raw content on every call.

    Extension (``.yaml``/``.yml`` vs ``.cfg``) is a tie-breaker only.
    """
    text = content.lstrip("\ufeff").lstrip()
    if not text:
        return "ini"

    first_line = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        first_line = stripped
        break
    if not first_line:
        return "ini"

    if first_line.startswith("["):
        return "ini"
    if (
        first_line.startswith("{")
        or first_line.startswith("---")
        or first_line.startswith("-")
    ):
        return "yaml"
    if ":" in first_line:
        return "yaml"

    ext = os.path.splitext(path)[1].lower()
    if ext in _YAML_CONFIG_EXTENSIONS:
        return "yaml"
    return "ini"


def _parse_ini(content: str) -> configparser.ConfigParser:
    """Parse INI text into ConfigParser."""
    config = _new_config_parser()
    config.read_string(content)
    return config


def _yaml_value_to_option(
    value: Any,
    logger: logging.Logger,
    section: str,
    option: str,
) -> Optional[str]:
    """Normalize a YAML value to a ConfigParser option string.

    ``null`` is omitted (returns ``None``) with a warning. Lists and dicts are
    ``json.dumps``-encoded so existing ``json.loads`` helpers keep working.
    Unsupported types (including ``datetime``/``date``) raise ``ValueError``.
    """
    if value is None:
        logger.warning("Ignoring null YAML option %s.%s", section, option)
        return None
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    raise ValueError(
        f"Unsupported YAML type {type(value).__name__} for {section}.{option}"
    )


def _set_yaml_option(
    config: configparser.ConfigParser,
    section: str,
    option: Any,
    value: Any,
    logger: logging.Logger,
) -> None:
    """Set one normalized YAML value on ``config``."""
    if not isinstance(option, str):
        raise ValueError(
            f"YAML config key must be a string, got {type(option).__name__}: {option!r}"
        )
    converted = _yaml_value_to_option(value, logger, section, option)
    if converted is None:
        return
    if section != "DEFAULT" and not config.has_section(section):
        config.add_section(section)
    config.set(section, option, converted)


def _parse_yaml(content: str, logger: logging.Logger) -> configparser.ConfigParser:
    """Parse YAML text and normalize it to ConfigParser.

    Mapping values become sections. Scalar, list, and null values at the root
    are stored under ``DEFAULT``. Non-mapping roots raise ``ValueError``.
    """
    data = yaml.load(content, Loader=_UniqueKeyLoader)
    config = _new_config_parser()
    if data is None:
        return config
    if not isinstance(data, dict):
        raise ValueError(
            f"acme_srv YAML config root must be a mapping, got {type(data).__name__}"
        )
    for raw_key, value in data.items():
        if not isinstance(raw_key, str):
            raise ValueError(
                "YAML config key must be a string, "
                f"got {type(raw_key).__name__}: {raw_key!r}"
            )
        if isinstance(value, dict):
            if raw_key != "DEFAULT" and not config.has_section(raw_key):
                config.add_section(raw_key)
            for option, option_value in value.items():
                _set_yaml_option(config, raw_key, option, option_value, logger)
        else:
            _set_yaml_option(config, "DEFAULT", raw_key, value, logger)
    return config


def _parse_config_content(
    content: str, path: str, logger: logging.Logger
) -> Tuple[configparser.ConfigParser, str]:
    """Detect format, parse, and return ``(config, format)``.

    Format is re-detected on every call. If INI parsing fails, the same content
    is retried as YAML. YAML parse errors are not caught.
    """
    cfg_format = _detect_config_format(content, path)
    logger.debug(
        "Detected acme_srv config format: %s (path=%s)",
        cfg_format,
        path,
    )
    if cfg_format == "yaml":
        return _parse_yaml(content, logger), "yaml"
    try:
        return _parse_ini(content), "ini"
    except configparser.Error:
        logger.debug(
            "INI parse failed, retrying as YAML (path=%s)",
            path,
        )
        return _parse_yaml(content, logger), "yaml"


def load_config(
    logger: logging.Logger = None, mfilter: str = None, cfg_file: str = None
) -> configparser.ConfigParser:
    """small configparser wrappter to load a config file"""
    global _LAST_LOADED_CFG  # pylint: disable=global-statement

    log = logger or logging.getLogger(__name__)
    log.debug(
        "Helper.load_config() start mfilter=%r cfg_file=%r",
        mfilter,
        cfg_file,
    )

    if cfg_file:
        source = "explicit"
        log.debug("Helper.load_config(): using explicit cfg_file=%s", cfg_file)
    elif "ACME_SRV_CONFIGFILE" in os.environ:
        cfg_file = os.environ["ACME_SRV_CONFIGFILE"]
        source = "ACME_SRV_CONFIGFILE"
        log.debug(
            "Helper.load_config(): using ACME_SRV_CONFIGFILE=%s",
            cfg_file,
        )
    else:
        cfg_file = _default_acme_srv_cfg_file(log)
        source = "default"

    log.debug("load_config(%s:%s)", mfilter, cfg_file)
    try:
        content = _read_config_file(cfg_file)
    except OSError:
        log.warning(
            "Helper.load_config(): could not read config file %s",
            cfg_file,
        )
        log.debug(
            "Helper.load_config() ended sections=%s",
            [],
        )
        # needed for backward compatibility - returns an empty configparser object
        return _new_config_parser()

    config, cfg_format = _parse_config_content(content, cfg_file, log)
    abs_path = os.path.abspath(cfg_file)
    _LAST_LOADED_CFG = (abs_path, source, cfg_format)

    # Only emit INFO when a configured app logger was passed. Module-level
    # load_config() runs before logger_setup(); flush via
    # log_loaded_acme_srv_cfg() afterwards.
    if logger is not None:
        _log_cfg_loaded_once(logger, abs_path, source, cfg_format)
    else:
        log.debug("Loaded acme_srv.cfg %s (%s, %s)", abs_path, source, cfg_format)
    log.debug(
        "Helper.load_config() ended sections=%s",
        list(config.sections()),
    )
    return config


def header_info_jsonify(logger: logging.Logger, header_info: str) -> Dict[str, str]:
    """jsonify header info"""
    logger.debug("Helper.header_info_json_parse()")

    header_info_dic = {}
    try:
        if isinstance(header_info, list) and "header_info" in header_info[-1]:
            header_info_dic = json.loads(header_info[-1]["header_info"])
    except Exception as err:
        logger.error("Could not parse header_info_field: %s", err)

    logger.debug(
        "Helper.header_info_json_parse() ended with: %s", bool(header_info_dic)
    )
    return header_info_dic


def header_info_lookup(logger, csr: str, header_info_field, key: str) -> str:
    """lookup header info"""
    logger.debug("Helper.header_info_lookup(%s)", key)

    # Lazy import to avoid circular dependency
    from .network import header_info_get  # pylint: disable=C0415

    result = None
    header_info = header_info_get(logger, csr=csr)

    if header_info:
        header_info_dic = header_info_jsonify(logger, header_info)
        if header_info_field in header_info_dic:
            for ele in header_info_dic[header_info_field].split(" "):
                if key in ele.lower():
                    result = ele.split("=", 1)[1]
                    break
        else:
            logger.warning(
                "Header_info_field not found in header info: %s", header_info_field
            )
    logger.debug("Helper.header_info_lookup(%s) ended with: %s", key, result)
    return result


def profile_lookup(logger: logging.Logger, csr: str) -> str:
    """get profile name from csr"""
    logger.debug("Helper.profile_lookup()")

    from acme2certifier.acme_srv.db_handler import DBstore  # pylint: disable=c0415

    dbstore = DBstore(logger=logger)

    try:
        result = dbstore.certificates_search(
            "csr", csr, ["id", "order_id", "order__profile"]
        )
    except Exception as err:
        logger.warning("Profile lookup failed with: %s", err)
        result = None
    if result and "order__profile" in result[0]:
        # we have a match - get profile name
        profile_name = result[0]["order__profile"]
    else:
        profile_name = None

    logger.debug("Helper.profile_lookup() ended with: %s", profile_name)
    return profile_name


def client_parameter_validate(
    logger, csr: str, cahandler, value: str, value_list: List[str]
) -> Tuple[str, str]:
    """select value from list"""
    logger.debug("Helper.client_parameter_validate(%s)", value)

    value_to_set = None
    error = None
    if cahandler.profiles:
        logger.debug("Helper.client_parameter_validate(): using profile")
        # get profile info
        client_parameter = profile_lookup(logger, csr)
    else:
        logger.debug("Helper.client_parameter_validate(): using header info")
        # get header info
        client_parameter = header_info_lookup(
            logger, csr, cahandler.header_info_field, value
        )
    if client_parameter:
        if client_parameter in value_list:
            value_to_set = client_parameter
        else:
            error = f'{value} "{client_parameter}" is not allowed'
    else:
        # header not set, use first value from list
        value_to_set = value_list[0]

    logger.debug(
        "Helper.client_parameter_validate(%s) ended with %s/%s",
        value,
        value_to_set,
        error,
    )
    return value_to_set, error


def config_dryrun_load(logger: logging.Logger, config_dic: Dict[str, str]):
    """load dryrun configuration"""
    logger.debug("Helper.config_dryrun_load()")

    dryrun = False
    dryrun_profilename = None

    if "DEFAULT" in config_dic and "dryrun" in config_dic["DEFAULT"]:
        if config_dic["DEFAULT"]["dryrun"].lower() in ["true", "false"]:
            dryrun = config_dic.getboolean("DEFAULT", "dryrun", fallback=False)
        elif config_dic["DEFAULT"]["dryrun"].lower() == "profile":
            if config_dic.get("DEFAULT", "dryrun_profile", fallback=None):
                dryrun_profilename = config_dic["DEFAULT"]["dryrun_profile"]
            else:
                logger.warning(
                    "Dryrun profile name not set in configuration, please set dryrun_profile parameter"
                )

    logger.debug(
        "Helper.config_dryrun_load() ended with: %s/%s", dryrun, dryrun_profilename
    )
    return dryrun, dryrun_profilename
