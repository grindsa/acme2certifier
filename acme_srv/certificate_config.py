# -*- coding: utf-8 -*-
"""Certificate Configuration - Dataclass-based configuration management"""

from dataclasses import dataclass
from typing import Dict, Optional, Any
from acme_srv.helper import load_config


@dataclass
class CertificateConfig:
    """
    Configuration dataclass for Certificate operations.

    This centralizes all configuration settings for the Certificate class
    and its components, providing type safety and clear documentation.

    Similar to the pattern used in challenge refactoring.
    """

    # Basic settings
    debug: bool = False
    server_name: Optional[str] = None

    # Certificate processing settings
    cert_operations_log: Optional[Any] = None
    cert_reusage_timeframe: int = 0
    cn2san_add: bool = False
    enrollment_timeout: int = 5

    # Path and URL settings
    path_dic: Optional[Dict[str, str]] = None
    retry_after: int = 600

    # Feature flags
    tnauthlist_support: bool = False

    # Hook configuration
    ignore_pre_hook_failure: bool = False
    ignore_post_hook_failure: bool = True
    ignore_success_hook_failure: bool = False

    def __post_init__(self):
        """Initialize default values that can't be set in field defaults"""
        if self.path_dic is None:
            self.path_dic = {"cert_path": "/acme/cert/"}

    @classmethod
    def from_legacy_params(cls, debug: bool = False, srv_name: str = None, **kwargs) -> 'CertificateConfig':
        """
        Create configuration from legacy parameters for backward compatibility.

        Args:
            debug: Debug mode flag
            srv_name: Server name
            **kwargs: Additional configuration parameters

        Returns:
            CertificateConfig instance with provided parameters
        """
        return cls(
            debug=debug,
            server_name=srv_name,
            **kwargs
        )

    @classmethod
    def from_config_file(cls, debug: bool = False, srv_name: str = None) -> 'CertificateConfig':
        """
        Create configuration by loading from config file.

        Args:
            debug: Debug mode flag
            srv_name: Server name

        Returns:
            CertificateConfig instance with values loaded from config file
        """
        # Load configuration from file
        config_dic = load_config()

        # Extract Certificate section parameters
        cert_reusage_timeframe = 0
        enrollment_timeout = 5
        cert_operations_log = None

        try:
            cert_reusage_timeframe = int(
                config_dic.get(
                    "Certificate",
                    "cert_reusage_timeframe",
                    fallback=cert_reusage_timeframe
                )
            )
        except Exception:
            pass  # Keep default value

        try:
            enrollment_timeout = int(
                config_dic.get(
                    "Certificate",
                    "enrollment_timeout",
                    fallback=enrollment_timeout
                )
            )
        except Exception:
            pass  # Keep default value

        cert_operations_log = config_dic.get(
            "Certificate", "cert_operations_log", fallback=cert_operations_log
        )
        if cert_operations_log:
            cert_operations_log = cert_operations_log.lower()

        # Extract Order section parameters
        tnauthlist_support = False
        if "Order" in config_dic:
            tnauthlist_support = config_dic.getboolean(
                "Order", "tnauthlist_support", fallback=False
            )

        # Extract CAhandler section parameters
        cn2san_add = False
        if (
            "CAhandler" in config_dic
            and config_dic.get("CAhandler", "handler_file", fallback=None)
            == "examples/ca_handler/asa_ca_handler.py"
        ):
            cn2san_add = True

        # Handle path_dic with url_prefix
        path_dic = {"cert_path": "/acme/cert/"}
        if "Directory" in config_dic and "url_prefix" in config_dic["Directory"]:
            path_dic = {
                k: config_dic["Directory"]["url_prefix"] + v
                for k, v in path_dic.items()
            }

        # Extract Hook section parameters
        ignore_pre_hook_failure = False
        ignore_post_hook_failure = True
        ignore_success_hook_failure = False

        if "Hooks" in config_dic:
            ignore_pre_hook_failure = config_dic.getboolean(
                "Hooks", "ignore_pre_hook_failure", fallback=False
            )
            ignore_post_hook_failure = config_dic.getboolean(
                "Hooks", "ignore_post_hook_failure", fallback=True
            )
            ignore_success_hook_failure = config_dic.getboolean(
                "Hooks", "ignore_success_hook_failure", fallback=False
            )

        return cls(
            debug=debug,
            server_name=srv_name,
            cert_operations_log=cert_operations_log,
            cert_reusage_timeframe=cert_reusage_timeframe,
            cn2san_add=cn2san_add,
            enrollment_timeout=enrollment_timeout,
            path_dic=path_dic,
            tnauthlist_support=tnauthlist_support,
            ignore_pre_hook_failure=ignore_pre_hook_failure,
            ignore_post_hook_failure=ignore_post_hook_failure,
            ignore_success_hook_failure=ignore_success_hook_failure
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary for easy access.

        Returns:
            Dictionary representation of configuration
        """
        return {
            'debug': self.debug,
            'server_name': self.server_name,
            'cert_operations_log': self.cert_operations_log,
            'cert_reusage_timeframe': self.cert_reusage_timeframe,
            'cn2san_add': self.cn2san_add,
            'enrollment_timeout': self.enrollment_timeout,
            'path_dic': self.path_dic,
            'retry_after': self.retry_after,
            'tnauthlist_support': self.tnauthlist_support,
            'ignore_pre_hook_failure': self.ignore_pre_hook_failure,
            'ignore_post_hook_failure': self.ignore_post_hook_failure,
            'ignore_success_hook_failure': self.ignore_success_hook_failure,
        }

    def update(self, **kwargs) -> 'CertificateConfig':
        """
        Create a new configuration instance with updated values.

        Args:
            **kwargs: Configuration parameters to update

        Returns:
            New CertificateConfig instance with updated values
        """
        current_dict = self.to_dict()
        current_dict.update(kwargs)
        return CertificateConfig(**current_dict)

    def apply_to_business_logic(self, business_logic) -> None:
        """
        Apply relevant configuration settings to business logic component.

        Args:
            business_logic: CertificateBusinessLogic instance to configure
        """
        business_logic.cert_reusage_timeframe = self.cert_reusage_timeframe
        business_logic.tnauthlist_support = self.tnauthlist_support
        business_logic.cn2san_add = self.cn2san_add

    def apply_to_manager(self, manager) -> None:
        """
        Apply relevant configuration settings to manager component.

        Args:
            manager: CertificateManager instance to configure
        """
        manager.cert_operations_log = self.cert_operations_log
        manager.tnauthlist_support = self.tnauthlist_support