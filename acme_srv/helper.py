# -*- coding: utf-8 -*-
"""
Backwards compatibility layer for acme2certifier helper functions.
This file imports all functions from the modular helpers structure
to maintain compatibility with existing code.
"""

# Encoding and base64 operations
from .helpers.encoding import (
    b64decode_pad,
    b64_decode,
    b64_encode,
    b64_url_encode,
    b64_url_recode,
    b64_url_decode,
    build_pem_file,
    convert_byte_to_string,
    convert_string_to_byte,
)

# Certificate operations
from .helpers.certificates import (
    cert_aki_get,
    cert_aki_pyopenssl_get,
    cert_load,
    cert_dates_get,
    cert_cn_get,
    cert_der2pem,
    cert_issuer_get,
    cert_pem2der,
    cert_pubkey_get,
    cert_san_pyopenssl_get,
    cert_san_get,
    cert_ski_pyopenssl_get,
    cert_ski_get,
    cryptography_version_get,
    cert_extensions_get,
    cert_extensions_py_openssl_get,
    cert_serial_get,
    pembundle_to_list,
    certid_asn1_get,
    certid_hex_get,
    certid_check,
)

# CSR operations
from .helpers.csr import (
    csr_load,
    csr_cn_get,
    csr_dn_get,
    csr_pubkey_get,
    csr_san_get,
    csr_san_byte_get,
    csr_extensions_get,
    csr_subject_get,
    csr_cn_lookup,
)

# Cryptographic operations
from .helpers.crypto import (
    decode_deserialize,
    decode_message,
    generate_random_string,
    jwk_thumbprint_get,
    sha256_hash,
    sha256_hash_hex,
    signature_check,
    string_sanitize,
)

# Date/time utilities
from .helpers.datetime_utils import (
    uts_now,
    uts_to_date_utc,
    date_to_uts_utc,
    date_to_datestr,
    datestr_to_date,
)

# Validation functions
from .helpers.validation import (
    dkeys_lower,
    fqdn_in_san_check,
    validate_csr,
    validate_email,
    validate_identifier,
    validate_ip,
    validate_fqdn,
    ip_validate,
    ipv6_chk,
    cn_validate,
)

# Network operations
from .helpers.network import (
    _fqdn_resolve,
    fqdn_resolve,
    ptr_resolve,
    dns_server_list_load,
    patched_create_connection,
    proxy_check,
    url_get_with_own_dns,
    allowed_gai_family,
    url_get_with_default_dns,
    url_get,
    txt_get,
    proxystring_convert,
    servercert_get,
    v6_adjust,
    header_info_get,
    get_url,
    parse_url,
    encode_url,
    request_operation,
)

# Configuration
from .helpers.config import (
    config_check,
    config_profile_load,
    config_eab_profile_load,
    config_headerinfo_load,
    config_enroll_config_log_load,
    config_allowed_domainlist_load,
    config_async_mode_load,
    config_proxy_load,
    load_config,
    header_info_jsonify,
    header_info_lookup,
    client_parameter_validate,
    profile_lookup,
)

# Logging utilities
from .helpers.logging_utils import (
    _logger_nonce_modify,
    _logger_certificate_modify,
    _logger_token_modify,
    _logger_challenges_modify,
    logger_info,
    logger_setup,
    print_debug,
    handle_exception,
)

# Plugin loaders
from .helpers.plugin_loader import ca_handler_load, eab_handler_load, hooks_load

# EAB functions
from .helpers.eab import (
    eab_profile_header_info_check,
    eab_profile_subject_string_check,
    eab_profile_subject_check,
    eab_profile_revocation_check,
    eab_profile_check,
    eab_profile_list_check,
    eab_profile_string_check,
)

# Domain utilities
from .helpers.domain_utils import (
    encode_domain,
    wildcard_domain_check,
    pattern_check,
    is_domain_whitelisted,
    allowed_domainlist_check,
    sancheck_lists_create,
)

# General utilities
from .helpers.utils import (
    error_dic_get,
    enrollment_config_log,
    radomize_parameter_list,
    handler_config_check,
)
