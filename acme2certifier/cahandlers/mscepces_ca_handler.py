# -*- coding: utf-8 -*-
"""CA handler for Microsoft CEP/CES (MS-XCEP + MS-WSTEP) over HTTPS."""

from __future__ import print_function

import base64
import hashlib
import importlib
import json
import os
import re
import subprocess
import tempfile
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

import requests

from acme2certifier.acme_srv.helper import (
    b64_url_recode,
    build_pem_file,
    config_eab_profile_load,
    config_enroll_config_log_load,
    config_option_load,
    config_profile_load,
    config_proxy_load,
    convert_byte_to_string,
    convert_string_to_byte,
    eab_profile_header_info_check,
    enrollment_config_log,
    handler_config_check,
    load_config,
    pkcs7_to_pem,
)
from acme2certifier.acme_srv.helpers.config import config_allowed_header_values_load
from acme2certifier.acme_srv.helpers.global_variables import CONFIGURATION_ERROR_DETAIL
from acme2certifier.acme_srv.helpers.kerberos_auth import KerberosAuthMixin

# KerberosAuthMixin resolves these from this module so tests can patch them.
_KERBEROS_RUNTIME = (os, tempfile, importlib, subprocess)

NS_SOAP = "http://www.w3.org/2003/05/soap-envelope"
NS_ADDR = "http://www.w3.org/2005/08/addressing"
NS_WST = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
NS_WSSE = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-wssecurity-secext-1.0.xsd"
)
NS_WSU = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-wssecurity-utility-1.0.xsd"
)
NS_XCEP = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"
NS_ENROLL = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment"
NS_AUTH = "http://schemas.xmlsoap.org/ws/2006/12/authorization"
NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"

ACTION_GET_POLICIES = (
    "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/"
    "IPolicy/GetPolicies"
)
ACTION_WSTEP_RST = (
    "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep"
)
TOKEN_TYPE_X509 = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-x509-token-profile-1.0#X509v3"
)
REQUEST_TYPE_ISSUE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"
REQUEST_TYPE_QUERY = (
    "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/QueryTokenStatus"
)
VALUE_TYPE_PKCS10 = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10"
ENCODING_BASE64 = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary"
)
PASSWORD_TEXT_TYPE = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-username-token-profile-1.0#PasswordText"
)

POLL_ID_SEPARATOR = "@@"
CHANNEL_BINDINGS_TLS_SERVER_END_POINT = "tls-server-end-point"

for _prefix, _uri in (
    ("s", NS_SOAP),
    ("a", NS_ADDR),
    ("wst", NS_WST),
    ("wsse", NS_WSSE),
    ("wsu", NS_WSU),
    ("xcep", NS_XCEP),
    ("enroll", NS_ENROLL),
    ("auth", NS_AUTH),
    ("xsi", NS_XSI),
):
    ET.register_namespace(_prefix, _uri)


def _local_name(tag: str) -> str:
    """Return local element name from Clark notation."""
    if tag and "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag or ""


def _find_first(root: ET.Element, local: str) -> Optional[ET.Element]:
    """Find first descendant with the given local name."""
    for element in root.iter():
        if _local_name(element.tag) == local:
            return element
    return None


def _find_all(root: ET.Element, local: str) -> List[ET.Element]:
    """Find all descendants with the given local name."""
    return [el for el in root.iter() if _local_name(el.tag) == local]


def _element_text(element: Optional[ET.Element]) -> Optional[str]:
    """Return stripped element text or None."""
    if element is None or element.text is None:
        return None
    text = element.text.strip()
    return text or None


def _soap_envelope(
    action: str,
    to_url: str,
    body_payload: ET.Element,
    username_token: Optional[Dict[str, str]] = None,
) -> bytes:
    """Build a SOAP 1.2 envelope with WS-Addressing headers."""
    envelope = ET.Element(ET.QName(NS_SOAP, "Envelope"))
    header = ET.SubElement(envelope, ET.QName(NS_SOAP, "Header"))

    action_el = ET.SubElement(header, ET.QName(NS_ADDR, "Action"))
    action_el.set(ET.QName(NS_SOAP, "mustUnderstand"), "1")
    action_el.text = action

    message_id = ET.SubElement(header, ET.QName(NS_ADDR, "MessageID"))
    message_id.text = f"urn:uuid:{uuid.uuid4()}"

    to_el = ET.SubElement(header, ET.QName(NS_ADDR, "To"))
    to_el.set(ET.QName(NS_SOAP, "mustUnderstand"), "1")
    to_el.text = to_url

    if username_token:
        security = ET.SubElement(header, ET.QName(NS_WSSE, "Security"))
        security.set(ET.QName(NS_SOAP, "mustUnderstand"), "1")
        token = ET.SubElement(security, ET.QName(NS_WSSE, "UsernameToken"))
        token.set(ET.QName(NS_WSU, "Id"), f"uuid-{uuid.uuid4()}")
        username_el = ET.SubElement(token, ET.QName(NS_WSSE, "Username"))
        username_el.text = username_token["username"]
        password_el = ET.SubElement(token, ET.QName(NS_WSSE, "Password"))
        password_el.set("Type", PASSWORD_TEXT_TYPE)
        password_el.text = username_token["password"]
        nonce_el = ET.SubElement(token, ET.QName(NS_WSSE, "Nonce"))
        nonce_el.text = username_token["nonce"]
        created_el = ET.SubElement(token, ET.QName(NS_WSU, "Created"))
        created_el.text = username_token["created"]

    body = ET.SubElement(envelope, ET.QName(NS_SOAP, "Body"))
    body.append(body_payload)
    return ET.tostring(envelope, encoding="utf-8", xml_declaration=True)


def _xcep_get_policies_body() -> ET.Element:
    """Build MS-XCEP GetPolicies body."""
    get_policies = ET.Element(ET.QName(NS_XCEP, "GetPolicies"))
    client = ET.SubElement(get_policies, ET.QName(NS_XCEP, "client"))
    last_update = ET.SubElement(client, ET.QName(NS_XCEP, "lastUpdate"))
    last_update.set(ET.QName(NS_XSI, "nil"), "true")
    preferred = ET.SubElement(client, ET.QName(NS_XCEP, "preferredLanguage"))
    preferred.set(ET.QName(NS_XSI, "nil"), "true")
    request_filter = ET.SubElement(get_policies, ET.QName(NS_XCEP, "requestFilter"))
    policy_oids = ET.SubElement(request_filter, ET.QName(NS_XCEP, "policyOIDs"))
    policy_oids.set(ET.QName(NS_XSI, "nil"), "true")
    client_version = ET.SubElement(request_filter, ET.QName(NS_XCEP, "clientVersion"))
    client_version.text = "0"
    server_version = ET.SubElement(request_filter, ET.QName(NS_XCEP, "serverVersion"))
    server_version.text = "0"
    return get_policies


def _parse_xcep_get_policies(response_xml: str) -> Dict[str, Any]:
    """Parse GetPoliciesResponse into templates, CES URIs, and CA certificates."""
    root = ET.fromstring(response_xml)
    fault = _find_first(root, "Fault")
    if fault is not None:
        reason = _element_text(_find_first(fault, "Text")) or "SOAP Fault"
        raise RuntimeError(f"XCEP SOAP Fault: {reason}")

    templates: List[str] = []
    for common_name in _find_all(root, "commonName"):
        name = _element_text(common_name)
        if name and name not in templates:
            templates.append(name)

    ces_uris: List[str] = []
    for uri_el in _find_all(root, "uri"):
        uri = _element_text(uri_el)
        if uri and uri not in ces_uris:
            ces_uris.append(uri)

    ca_certificates: List[str] = []
    for ca_el in _find_all(root, "cA"):
        cert_el = _find_first(ca_el, "certificate")
        pem = _certificate_element_to_pem(_element_text(cert_el))
        if pem and pem not in ca_certificates:
            ca_certificates.append(pem)

    return {
        "templates": templates,
        "ces_uris": ces_uris,
        "ca_certificates": ca_certificates,
    }


def _certificate_element_to_pem(cert_b64: Optional[str]) -> Optional[str]:
    """Decode XCEP ``cA/certificate`` (base64 DER) to PEM."""
    if not cert_b64:
        return None
    from cryptography import x509  # pylint: disable=C0415
    from cryptography.hazmat.primitives import serialization  # pylint: disable=C0415

    cleaned = re.sub(r"\s+", "", cert_b64)
    try:
        raw = base64.b64decode(cleaned)
        cert = x509.load_der_x509_certificate(raw)
    except Exception:
        return None
    return convert_byte_to_string(cert.public_bytes(serialization.Encoding.PEM))


def _pem_certificates_split(pem_bundle: str) -> List[str]:
    """Split a PEM bundle into individual certificate PEM strings."""
    return re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        pem_bundle,
        flags=re.DOTALL,
    )


def _cert_bundle_with_ca(leaf_pem: str, ca_pem_list: List[str]) -> str:
    """Append CA PEMs to the leaf, skipping duplicates."""
    bundle = leaf_pem if leaf_pem.endswith("\n") else leaf_pem + "\n"
    existing = set(_pem_certificates_split(bundle))
    for ca_pem in ca_pem_list:
        for cert_pem in _pem_certificates_split(ca_pem):
            if cert_pem in existing:
                continue
            bundle += cert_pem if cert_pem.endswith("\n") else cert_pem + "\n"
            existing.add(cert_pem)
    return bundle


def _wstep_issue_body(pkcs10_b64: str, template: Optional[str]) -> ET.Element:
    """Build MS-WSTEP RequestSecurityToken Issue body."""
    rst = ET.Element(ET.QName(NS_WST, "RequestSecurityToken"))
    token_type = ET.SubElement(rst, ET.QName(NS_WST, "TokenType"))
    token_type.text = TOKEN_TYPE_X509
    request_type = ET.SubElement(rst, ET.QName(NS_WST, "RequestType"))
    request_type.text = REQUEST_TYPE_ISSUE
    binary_token = ET.SubElement(rst, ET.QName(NS_WSSE, "BinarySecurityToken"))
    binary_token.set("ValueType", VALUE_TYPE_PKCS10)
    binary_token.set("EncodingType", ENCODING_BASE64)
    binary_token.set(ET.QName(NS_WSU, "Id"), f"uuid-{uuid.uuid4()}")
    binary_token.text = pkcs10_b64

    if template:
        additional = ET.SubElement(rst, ET.QName(NS_AUTH, "AdditionalContext"))
        item = ET.SubElement(additional, ET.QName(NS_AUTH, "ContextItem"))
        item.set("Name", "CertificateTemplate")
        value = ET.SubElement(item, ET.QName(NS_AUTH, "Value"))
        value.text = template

    return rst


def _wstep_query_body(request_id: str) -> ET.Element:
    """Build MS-WSTEP QueryTokenStatus body."""
    rst = ET.Element(ET.QName(NS_WST, "RequestSecurityToken"))
    request_type = ET.SubElement(rst, ET.QName(NS_WST, "RequestType"))
    request_type.text = REQUEST_TYPE_QUERY
    request_id_el = ET.SubElement(rst, ET.QName(NS_ENROLL, "RequestID"))
    request_id_el.text = str(request_id)
    return rst


def _parse_wstep_response(response_xml: str) -> Dict[str, Any]:
    """Parse RequestSecurityTokenResponseCollection into a structured result."""
    root = ET.fromstring(response_xml)
    fault = _find_first(root, "Fault")
    if fault is not None:
        reason = _element_text(_find_first(fault, "Text")) or "SOAP Fault"
        raise RuntimeError(f"WSTEP SOAP Fault: {reason}")

    response = _find_first(root, "RequestSecurityTokenResponse")
    if response is None:
        raise RuntimeError("WSTEP response missing RequestSecurityTokenResponse")

    disposition = _element_text(_find_first(response, "DispositionMessage")) or ""
    request_id = _element_text(_find_first(response, "RequestID"))

    token_text = None
    requested_token = _find_first(response, "RequestedSecurityToken")
    if requested_token is not None:
        requested_binary = _find_first(requested_token, "BinarySecurityToken")
        requested_text = _element_text(requested_binary)
        if requested_text:
            token_text = requested_text.replace("\r", "")

    reference_uri = None
    reference = _find_first(response, "Reference")
    if reference is not None:
        for key, value in reference.attrib.items():
            if _local_name(key) == "URI":
                reference_uri = value
                break

    disposition_lower = disposition.lower()
    if "denied" in disposition_lower or "rejected" in disposition_lower:
        status = "denied"
    elif token_text:
        status = "issued"
    elif "pending" in disposition_lower or request_id:
        status = "pending"
    else:
        status = "unknown"

    return {
        "status": status,
        "disposition": disposition,
        "request_id": request_id,
        "token": token_text,
        "reference": reference_uri,
    }


def _csr_to_pkcs10_b64(logger: object, csr: str) -> str:
    """Convert ACME CSR (urlsafe b64 or PEM) to standard base64 PKCS#10 DER."""
    from cryptography import x509  # pylint: disable=C0415
    from cryptography.hazmat.primitives import serialization  # pylint: disable=C0415

    csr_input = csr.strip()
    if "BEGIN" in csr_input:
        csr_obj = x509.load_pem_x509_csr(convert_string_to_byte(csr_input))
    else:
        pem = build_pem_file(
            logger, None, b64_url_recode(logger, csr_input), True, True
        )
        csr_obj = x509.load_pem_x509_csr(convert_string_to_byte(pem))
    der = csr_obj.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(der).decode("ascii")


def _token_to_pem_bundle(
    logger: object, token_b64: str
) -> Tuple[Optional[str], Optional[str]]:
    """Convert WSTEP BinarySecurityToken into (cert_bundle_pem, cert_raw_b64)."""
    from cryptography import x509  # pylint: disable=C0415
    from cryptography.hazmat.primitives import serialization  # pylint: disable=C0415

    cleaned = re.sub(r"\s+", "", token_b64)
    try:
        raw = base64.b64decode(cleaned)
    except Exception:
        raw = convert_string_to_byte(token_b64)

    if isinstance(raw, str):
        text = raw
        raw_bytes = convert_string_to_byte(raw)
    else:
        raw_bytes = raw
        try:
            text = raw.decode("ascii")
        except Exception:
            text = ""

    if "BEGIN CERTIFICATE" in text or "BEGIN PKCS7" in text:
        try:
            pem_bundle = pkcs7_to_pem(logger, text, "string")
            leaf = _leaf_pem_from_bundle(pem_bundle)
            return (pem_bundle, _pem_to_raw_b64(leaf))
        except Exception:
            try:
                cert = x509.load_pem_x509_certificate(convert_string_to_byte(text))
                leaf = convert_byte_to_string(
                    cert.public_bytes(serialization.Encoding.PEM)
                )
                return (leaf, _pem_to_raw_b64(leaf))
            except Exception:
                pass

    try:
        cert = x509.load_der_x509_certificate(raw_bytes)
        leaf = convert_byte_to_string(cert.public_bytes(serialization.Encoding.PEM))
        return (leaf, _pem_to_raw_b64(leaf))
    except Exception:
        pass

    try:
        pem_bundle = pkcs7_to_pem(logger, raw_bytes, "string")
        leaf = _leaf_pem_from_bundle(pem_bundle)
        return (pem_bundle, _pem_to_raw_b64(leaf))
    except Exception:
        return (None, None)


def _leaf_pem_from_bundle(pem_bundle: str) -> str:
    """Return the first PEM certificate from a bundle."""
    match = re.search(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        pem_bundle,
        flags=re.DOTALL,
    )
    return match.group(0) + "\n" if match else pem_bundle


def _pem_to_raw_b64(pem: str) -> str:
    """Strip PEM headers and newlines for ACME cert_raw."""
    raw = pem.replace("-----BEGIN CERTIFICATE-----", "")
    raw = raw.replace("-----END CERTIFICATE-----", "")
    raw = raw.replace("\r", "").replace("\n", "").strip()
    return raw


def _poll_identifier_encode(request_id: str, reference: str) -> str:
    """Encode pending poll identifier."""
    return f"{request_id}{POLL_ID_SEPARATOR}{reference}"


def _poll_identifier_decode(
    poll_identifier: str,
) -> Tuple[Optional[str], Optional[str]]:
    """Decode pending poll identifier into (request_id, reference)."""
    if not poll_identifier or POLL_ID_SEPARATOR not in poll_identifier:
        return (poll_identifier or None, None)
    request_id, reference = poll_identifier.split(POLL_ID_SEPARATOR, 1)
    return (request_id or None, reference or None)


def _username_token_fields(username: str, password: str) -> Dict[str, str]:
    """Build WS-Security UsernameToken field values."""
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce_raw = f"{username}:{password}:{created}".encode("utf-8")
    nonce = base64.b64encode(hashlib.md5(nonce_raw).digest()).decode("ascii")
    return {
        "username": username,
        "password": password,
        "nonce": nonce,
        "created": created,
    }


def gssapi_channel_bindings_supported() -> bool:
    """Return True when requests_gssapi supports channel_bindings."""
    try:
        requests_gssapi = importlib.import_module("requests_gssapi")
        auth_cls = getattr(requests_gssapi, "HTTPSPNEGOAuth", None)
        if auth_cls is None:
            return False
        import inspect  # pylint: disable=C0415

        return "channel_bindings" in inspect.signature(auth_cls).parameters
    except Exception:
        return False


class CAhandler(KerberosAuthMixin):
    """Microsoft CEP/CES CA handler."""

    KINIT_TIMEOUT_SECONDS = 30
    CERT_FETCH_ERROR = "Could not get certificate from CA server"
    KRB5_CONFIG_MISSING_LOG = "Configured krb5_config does not exist: %s"
    _KRB5_CACHE_EXTRA_ATTR = "_gssapi_creds"
    _KRB5_KINIT_REQUIRE_CONFIG_FILE = True

    def __init__(self, _debug: bool = False, logger: object = None):
        self.logger = logger
        self.ces_url = None
        self.cep_url = None
        self.ces_username = None
        self.ces_password = None
        self.user = None
        self.password = None
        self.auth_method = "gssapi"
        self.gssapi_channel_bindings = "auto"
        self.ca_bundle = True
        self.ca_certificates = None
        self.verify = True
        self.template = None
        self.allowed_templates: List[str] = []
        self.ca_templates_check = "warn"
        self.krb5_principal = None
        self.krb5_keytab = None
        self.krb5_cache = None
        self.krb5_config = None
        self.krb5_kinit_path = "kinit"
        self.proxy = None
        self.header_info_field = False
        self.eab_handler = None
        self.eab_profiling = False
        self.enrollment_config_log = False
        self.enrollment_config_log_skip_list = []
        self.profiles = {}
        self.timeout = 30
        self._krb5_cache_is_temporary = False
        self._gssapi_creds = None
        self._policies_cache: Optional[Dict[str, Any]] = None
        self.profile_mapping_field = "template"

    def __enter__(self):
        """Makes CAhandler a Context Manager."""
        if not self.ces_url:
            self._config_load()
        return self

    def __exit__(self, *args):
        """Close the connection at the end of the context."""

    def _config_load(self) -> None:
        """Load config from file."""
        self.logger.debug("CAhandler._config_load()")
        config_dic = load_config(self.logger, "CAhandler")

        if "CAhandler" in config_dic:
            self.ces_url = config_option_load(
                self.logger, config_dic, "ces_url", current=self.ces_url
            )
            self.cep_url = config_option_load(
                self.logger, config_dic, "cep_url", current=self.cep_url
            )
            self.ces_username = config_option_load(
                self.logger, config_dic, "ces_username", current=self.ces_username
            )
            self.ces_password = config_option_load(
                self.logger, config_dic, "ces_password", current=self.ces_password
            )
            # KerberosAuthMixin expects self.user / self.password
            self.user = self.ces_username
            self.password = self.ces_password
            self._config_kerberos_parameters_load(config_dic)
            self._config_parameters_load(config_dic)
            self.eab_profiling, self.eab_handler = config_eab_profile_load(
                self.logger, config_dic
            )
            self.profiles = config_profile_load(self.logger, config_dic)
            self._config_headerinfo_load(config_dic)
            self._config_allowed_templates_load(config_dic)

        self._config_proxy_load(config_dic)
        self.logger.debug("CAhandler._config_load() ended")

    def _config_kerberos_parameters_load(self, config_dic: Dict[str, str]) -> None:
        """Load kerberos related parameters from env or config."""
        self.logger.debug("CAhandler._config_kerberos_parameters_load()")
        self.krb5_principal = config_option_load(
            self.logger, config_dic, "krb5_principal", current=self.krb5_principal
        )
        self.krb5_keytab = config_option_load(
            self.logger, config_dic, "krb5_keytab", current=self.krb5_keytab
        )
        self.krb5_cache = config_option_load(
            self.logger, config_dic, "krb5_cache", current=self.krb5_cache
        )
        self.krb5_config = config_option_load(
            self.logger, config_dic, "krb5_config", current=self.krb5_config
        )
        self.krb5_kinit_path = config_option_load(
            self.logger, config_dic, "krb5_kinit_path", current=self.krb5_kinit_path
        )
        self.logger.debug("CAhandler._config_kerberos_parameters_load() ended")

    def _config_parameters_load(self, config_dic: Dict[str, str]) -> None:
        """Load handler parameters."""
        self.logger.debug("CAhandler._config_parameters_load()")
        self.template = config_dic.get(
            "CAhandler", self.profile_mapping_field, fallback=self.template
        )
        auth_method = config_dic.get(
            "CAhandler", "auth_method", fallback=self.auth_method
        )
        if isinstance(auth_method, str):
            auth_method = auth_method.lower()
        if auth_method in ["gssapi", "username_password"]:
            self.auth_method = auth_method
        else:
            self.logger.warning(
                "Unknown auth_method '%s'. Falling back to 'gssapi'.", auth_method
            )
            self.auth_method = "gssapi"

        channel_bindings_mode = config_dic.get(
            "CAhandler",
            "gssapi_channel_bindings",
            fallback=self.gssapi_channel_bindings,
        )
        if isinstance(channel_bindings_mode, str):
            channel_bindings_mode = channel_bindings_mode.lower()
        if channel_bindings_mode in ["auto", "on", "off"]:
            self.gssapi_channel_bindings = channel_bindings_mode
        else:
            self.logger.warning(
                "Invalid gssapi_channel_bindings '%s'; using 'auto'.",
                channel_bindings_mode,
            )
            self.gssapi_channel_bindings = "auto"

        self.ca_bundle = config_dic.get(
            "CAhandler", "ca_bundle", fallback=self.ca_bundle
        )
        self.ca_certificates = config_option_load(
            self.logger, config_dic, "ca_certificates", current=self.ca_certificates
        )
        self.verify = config_dic.getboolean("CAhandler", "verify", fallback=True)
        self.timeout = config_dic.getint("CAhandler", "timeout", fallback=self.timeout)
        mode = config_dic.get(
            "CAhandler", "ca_templates_check", fallback=self.ca_templates_check
        )
        if isinstance(mode, str):
            mode = mode.lower()
        if mode in ["warn", "on", "off"]:
            self.ca_templates_check = mode
        (
            self.enrollment_config_log,
            self.enrollment_config_log_skip_list,
        ) = config_enroll_config_log_load(self.logger, config_dic)
        self._security_configuration_warnings_log()
        self.logger.debug("CAhandler._config_parameters_load() ended")

    def _security_configuration_warnings_log(self) -> None:
        """Log non-blocking security risk warnings."""
        self.logger.debug("CAhandler._security_configuration_warnings_log()")
        if self.verify is False:
            self.logger.warning(
                "TLS certificate verification is disabled (verify=False). "
                "Enrollment traffic to CEP/CES is vulnerable to MITM. "
                "Prefer ca_bundle / system trust."
            )
        self.logger.debug("CAhandler._security_configuration_warnings_log() ended")

    def _config_headerinfo_load(self, config_dic: Dict[str, str]) -> None:
        """Load Order.header_info_list."""
        self.logger.debug("CAhandler._config_headerinfo_load()")
        if (
            "Order" in config_dic
            and "header_info_list" in config_dic["Order"]
            and config_dic["Order"]["header_info_list"]
        ):
            try:
                self.header_info_field = json.loads(
                    config_dic["Order"]["header_info_list"]
                )[0]
            except Exception as err_:
                self.logger.warning(
                    "Failed to parse header_info_list from configuration: %s",
                    err_,
                )
        self.logger.debug("CAhandler._config_headerinfo_load() ended")

    def _config_allowed_templates_load(self, config_dic: Dict[str, str]) -> None:
        """Load template allowlist."""
        self.logger.debug("CAhandler._config_allowed_templates_load()")
        order_values = config_allowed_header_values_load(self.logger, config_dic)
        if order_values:
            self.allowed_templates = order_values
            return

        if (
            "CAhandler" not in config_dic
            or "allowed_templates" not in config_dic["CAhandler"]
        ):
            return

        self.logger.warning(
            "CAhandler allowed_templates is deprecated for header allowlisting; "
            "move the list to [Order] allowed_header_values"
        )
        try:
            loaded = json.loads(config_dic.get("CAhandler", "allowed_templates"))
            if isinstance(loaded, list):
                self.allowed_templates = [str(item) for item in loaded]
        except Exception as err_:
            self.logger.warning(
                "Failed to parse allowed_templates from configuration: %s", err_
            )
            self.allowed_templates = []

    def _config_proxy_load(self, config_dic: Dict[str, str]) -> None:
        """Load proxy settings for CES/CEP URLs."""
        self.logger.debug("CAhandler._config_proxy_load()")
        host_ref = self.ces_url or self.cep_url or ""
        self.proxy = config_proxy_load(self.logger, config_dic, host_ref)
        self.logger.debug("CAhandler._config_proxy_load() ended")

    def _https_url_check(self, url: Optional[str], label: str) -> Optional[str]:
        """Require HTTPS for configured endpoints."""
        self.logger.debug("CAhandler._https_url_check()")
        if not url:
            return None
        if url.strip().lower().startswith("https://"):
            return None
        error = (
            f"{label} must use HTTPS (got '{url}'). "
            "Cleartext HTTP is not supported for CEP/CES."
        )
        self.logger.error(error)
        return error

    def _credentials_are_configured(self) -> bool:
        """Return True when auth credentials are complete."""
        self.logger.debug("CAhandler._credentials_are_configured()")
        if self.auth_method == "gssapi" and self._kerberos_keytab_is_configured():
            return True
        return bool(self.user and self.password)

    def _allowed_templates_check(self) -> Optional[str]:
        """Enforce configured allowed_templates allowlist."""
        self.logger.debug("CAhandler._allowed_templates_check()")
        if not self.allowed_templates:
            return None
        if self.template not in self.allowed_templates:
            return (
                f"Template '{self.template}' is not in allowed_templates: "
                f"{self.allowed_templates}"
            )
        return None

    def _tls_verify(self):
        """Return requests verify argument."""
        self.logger.debug("CAhandler._tls_verify()")
        if self.verify is False:
            return False
        if self.ca_bundle not in (None, True, False, ""):
            return self.ca_bundle
        return True

    def _gssapi_creds_from_password(self) -> Any:
        """Acquire initiator creds via gssapi.raw.acquire_cred_with_password."""
        self.logger.debug("CAhandler._gssapi_creds_from_password()")
        try:
            gssapi = importlib.import_module("gssapi")
        except Exception as err:
            raise RuntimeError(
                f"gssapi module is required for gssapi password authentication: {err}"
            ) from err
        if not (self.user and self.password):
            raise RuntimeError(
                "ces_username and ces_password are required for GSSAPI password auth"
            )
        # Prefer krb5 for password acquire; SPNEGO second (Certsrv uses SPNEGO).
        # HTTPSPNEGOAuth still wraps with SPNEGO by default.
        # ces_username must be a Kerberos principal (user@REALM), not DOMAIN\user.
        mech_candidates = (
            ("krb5", "1.2.840.113554.1.2.2"),
            ("spnego", "1.3.6.1.5.5.2"),
        )
        errors: List[str] = []
        name = gssapi.Name(self.user, gssapi.NameType.user)
        for mech_name, oid_str in mech_candidates:
            try:
                oid = gssapi.OID.from_int_seq(oid_str)
                # pylint: disable=e1101
                cred = gssapi.raw.acquire_cred_with_password(
                    name,
                    self.password.encode("utf-8"),
                    mechs=[oid],
                    usage="initiate",
                )
                self.logger.debug(
                    "GSSAPI password credentials acquired for principal '%s' (%s)",
                    self.user,
                    mech_name,
                )
                return cred.creds
            except Exception as err:
                errors.append(f"{mech_name}: {type(err).__name__}: {err}")
        raise RuntimeError(
            "Failed to acquire GSSAPI credentials with password: " + "; ".join(errors)
        )

    def _session_auth(self):
        """Build requests auth object for transport authentication."""
        self.logger.debug("CAhandler._session_auth(%s)", self.auth_method)
        if self.auth_method != "gssapi":
            return None

        try:
            requests_gssapi = importlib.import_module("requests_gssapi")
        except Exception as err:
            raise RuntimeError(
                f"requests_gssapi is required for gssapi authentication: {err}"
            ) from err
        kwargs: Dict[str, Any] = {}
        if self._gssapi_creds is not None:
            raw = getattr(self._gssapi_creds, "creds", self._gssapi_creds)
            kwargs["creds"] = raw
        elif self.user and self.password:
            # In-process fallback when password kinit did not leave a ccache
            # (same approach as Certsrv._set_credentials). Runs under
            # _kerberos_runtime_environment so KRB5_CONFIG is scoped.
            kwargs["creds"] = self._gssapi_creds_from_password()
        channel_bindings, channel_error = self._gssapi_channel_bindings_resolve()
        if channel_error:
            raise RuntimeError(channel_error)
        if channel_bindings:
            kwargs["channel_bindings"] = channel_bindings
        if "creds" not in kwargs:
            raise RuntimeError(
                "GSSAPI authentication has no credentials: password kinit failed "
                "and in-process password acquire is unavailable. Set ces_username "
                "to a Kerberos principal (user@REALM), or configure "
                "krb5_principal/krb5_keytab."
            )
        return requests_gssapi.HTTPSPNEGOAuth(**kwargs)

    def _gssapi_channel_bindings_resolve(self) -> Tuple[Optional[str], Optional[str]]:
        """Resolve gssapi_channel_bindings mode."""
        self.logger.debug("CAhandler._gssapi_channel_bindings_resolve()")
        if self.auth_method != "gssapi" or self.gssapi_channel_bindings == "off":
            return (None, None)
        supported = gssapi_channel_bindings_supported()
        if self.gssapi_channel_bindings == "on":
            if not supported:
                return (
                    None,
                    "gssapi_channel_bindings=on requires requests-gssapi >= 1.4.0 "
                    "with channel_bindings support.",
                )
            return (CHANNEL_BINDINGS_TLS_SERVER_END_POINT, None)
        if supported:
            return (CHANNEL_BINDINGS_TLS_SERVER_END_POINT, None)
        self.logger.warning(
            "requests-gssapi does not support channel_bindings; continuing without."
        )
        return (None, None)

    def _username_token(self) -> Optional[Dict[str, str]]:
        """Return UsernameToken fields for SOAP message auth."""
        self.logger.debug("CAhandler._username_token()")
        if self.auth_method != "username_password":
            return None
        if not (self.ces_username and self.ces_password):
            raise RuntimeError(
                "ces_username and ces_password are required for "
                "username_password authentication"
            )
        return _username_token_fields(self.ces_username, self.ces_password)

    def _soap_post(self, url: str, action: str, body_payload: ET.Element) -> str:
        """POST a SOAP envelope and return response text."""
        self.logger.debug("CAhandler._soap_post(%s, %s)", url, action)
        headers = {"Content-Type": "application/soap+xml; charset=utf-8"}
        data = _soap_envelope(action, url, body_payload, self._username_token())
        response = requests.post(
            url,
            data=data,
            headers=headers,
            auth=self._session_auth(),
            verify=self._tls_verify(),
            proxies=self.proxy,
            timeout=self.timeout,
        )
        if response.status_code == 500 and response.text:
            # SOAP Faults are often returned as HTTP 500.
            return response.text
        response.raise_for_status()
        return response.text

    @contextmanager
    def _kerberos_runtime_environment(self):
        """Scope KRB5_CONFIG for SPNEGO/TGS."""
        previous = os.environ.get("KRB5_CONFIG")
        krb5_config = self._kerberos_config_path_resolve()
        if krb5_config:
            os.environ["KRB5_CONFIG"] = krb5_config
        try:
            yield
        finally:
            if previous is None:
                os.environ.pop("KRB5_CONFIG", None)
            else:
                os.environ["KRB5_CONFIG"] = previous

    def _kerberos_gssapi_creds_from_cache(
        self,
    ) -> Tuple[Optional[object], Optional[str]]:
        """Load initiate GSSAPI credentials from the prepared ccache."""
        if self.auth_method != "gssapi":
            return (None, None)

        ccache_file = self._kerberos_ccache_path(self.krb5_cache)
        if not ccache_file:
            if self._kerberos_keytab_is_configured():
                return (None, "Kerberos ccache is not available")
            return (None, None)

        try:
            gssapi = importlib.import_module("gssapi")
        except Exception as err:
            return (None, f"gssapi module is required for gssapi authentication: {err}")

        try:
            credentials_class = getattr(gssapi, "Credentials", None)
            if credentials_class is None:
                return (None, "gssapi.Credentials is required to load credentials.")
            creds = credentials_class(usage="initiate", store={"ccache": ccache_file})
            return (creds, None)
        except Exception as err:
            return (None, f"Failed to load GSSAPI credentials from ccache: {err}")

    def _kerberos_bind_gssapi_creds(
        self,
    ) -> Tuple[Optional[object], Optional[str]]:
        """Load ccache creds; password mode may fall back to in-process acquire.

        Homebrew MIT ``kinit`` writes an MIT ccache that Apple GSS (default
        ``python-gssapi`` on macOS) often cannot read. In password mode, clear
        the unusable ccache and let ``_session_auth`` acquire via
        ``acquire_cred_with_password`` instead of failing enroll/poll.
        """
        gssapi_creds, gssapi_creds_error = self._kerberos_gssapi_creds_from_cache()
        if not gssapi_creds_error:
            return (gssapi_creds, None)

        self.logger.error("Kerberos credential load failed: %s", gssapi_creds_error)
        if self._kerberos_keytab_is_configured():
            self._kerberos_cleanup_temporary_ccache()
            return (None, gssapi_creds_error)

        self.logger.warning(
            "Ccache credentials unreadable after password kinit; "
            "falling back to in-process GSSAPI password authentication"
        )
        self._kerberos_cleanup_temporary_ccache()
        return (None, None)

    def _kerberos_prepare_gssapi_password_backend(self) -> Optional[str]:
        """Prepare GSSAPI creds for user/password via kinit."""
        if not (self.user and self.password):
            return None
        if self.krb5_config and not self._kerberos_config_path_resolve():
            return "Configured krb5_config does not exist."
        ccache_file = self._kerberos_ccache_prepare()
        if self._kerberos_acquire_with_kinit_password(ccache_file):
            return None
        self._kerberos_cleanup_temporary_ccache()
        self.logger.warning(
            "Password kinit unavailable; falling back to in-process GSSAPI password auth"
        )
        return None

    def _kerberos_prepare_gssapi_backend(self) -> Optional[str]:
        """Prepare kerberos credentials for GSSAPI."""
        if self.auth_method != "gssapi":
            return None
        if not self._kerberos_keytab_is_configured():
            return self._kerberos_prepare_gssapi_password_backend()
        return self._kerberos_acquire_keytab_credentials(
            gssapi_required_error=(
                "gssapi module is required for gssapi keytab authentication."
            )
        )

    def _xcep_get_policies(self) -> Dict[str, Any]:
        """Call CEP GetPolicies (cached for the current enroll/poll)."""
        if self._policies_cache is not None:
            return self._policies_cache
        if not self.cep_url:
            raise RuntimeError("cep_url is not configured")
        body = _xcep_get_policies_body()
        response_xml = self._soap_post(self.cep_url, ACTION_GET_POLICIES, body)
        self._policies_cache = _parse_xcep_get_policies(response_xml)
        return self._policies_cache

    def _ca_certificates_from_file(self) -> List[str]:
        """Load optional PEM CA chain from ``ca_certificates`` file."""
        if not self.ca_certificates:
            return []
        if not os.path.exists(self.ca_certificates):
            self.logger.warning(
                "ca_certificates file does not exist: %s", self.ca_certificates
            )
            return []
        try:
            with open(self.ca_certificates, "r", encoding="utf-8") as fso:
                content = fso.read()
        except OSError as err:
            self.logger.warning("Failed to read ca_certificates: %s", err)
            return []
        return [
            pem if pem.endswith("\n") else pem + "\n"
            for pem in _pem_certificates_split(content)
        ]

    def _ca_certificates_from_cep(self) -> List[str]:
        """Fetch issuing CA certificate(s) from CEP GetPolicies."""
        if not self.cep_url:
            return []
        try:
            policies = self._xcep_get_policies()
        except Exception as err:
            self.logger.warning("Failed to fetch CA certificates from CEP: %s", err)
            return []
        return list(policies.get("ca_certificates") or [])

    def _ca_chain_pem_list(self) -> List[str]:
        """Build CA PEM list from CEP and/or ``ca_certificates`` file."""
        ca_list: List[str] = []
        for pem in self._ca_certificates_from_cep() + self._ca_certificates_from_file():
            normalized = pem if pem.endswith("\n") else pem + "\n"
            if normalized not in ca_list:
                ca_list.append(normalized)
        return ca_list

    def _ca_templates_membership_check(self) -> Optional[str]:
        """Optionally validate template against CEP policy."""
        if self.ca_templates_check == "off" or not self.cep_url or not self.template:
            return None
        try:
            policies = self._xcep_get_policies()
        except Exception as err:
            message = f"CEP GetPolicies failed: {err}"
            if self.ca_templates_check == "on":
                return message
            self.logger.warning(message)
            return None

        templates = policies.get("templates") or []
        if self.template in templates:
            return None
        message = (
            f"Template '{self.template}' was not found in CEP policy templates: "
            f"{templates}"
        )
        if self.ca_templates_check == "on":
            return message
        self.logger.warning(message)
        return None

    def _wstep_issue(self, csr: str) -> Dict[str, Any]:
        """Submit CSR via WSTEP Issue."""
        pkcs10_b64 = _csr_to_pkcs10_b64(self.logger, csr)
        body = _wstep_issue_body(pkcs10_b64, self.template)
        response_xml = self._soap_post(self.ces_url, ACTION_WSTEP_RST, body)
        return _parse_wstep_response(response_xml)

    def _wstep_poll(self, request_id: str, ces_url: str) -> Dict[str, Any]:
        """Poll pending request via WSTEP QueryTokenStatus."""
        body = _wstep_query_body(request_id)
        response_xml = self._soap_post(ces_url, ACTION_WSTEP_RST, body)
        return _parse_wstep_response(response_xml)

    def _result_from_wstep(
        self, result: Dict[str, Any]
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """Map WSTEP result to enroll/poll tuple parts."""
        status = result.get("status")
        if status == "issued":
            token = result.get("token")
            if not token:
                return (self.CERT_FETCH_ERROR, None, None, None)
            cert_bundle, cert_raw = _token_to_pem_bundle(self.logger, token)
            if not cert_raw:
                return (
                    "Failed to parse certificate from WSTEP response",
                    None,
                    None,
                    None,
                )
            ca_list = self._ca_chain_pem_list()
            if ca_list:
                cert_bundle = _cert_bundle_with_ca(cert_bundle or "", ca_list)
            elif not self.cep_url and not self.ca_certificates:
                self.logger.warning(
                    "No CA chain appended: configure cep_url (preferred) or "
                    "ca_certificates PEM file."
                )
            return (None, cert_bundle, cert_raw, None)

        if status == "pending":
            request_id = result.get("request_id")
            if not request_id:
                return ("Pending response missing RequestID", None, None, None)
            reference = result.get("reference") or self.ces_url
            return (
                None,
                None,
                None,
                _poll_identifier_encode(str(request_id), reference),
            )

        if status == "denied":
            detail = result.get("disposition") or "Request denied"
            return (f"Certificate request denied: {detail}", None, None, None)

        return (
            f"Unexpected WSTEP disposition: {result.get('disposition')}",
            None,
            None,
            None,
        )

    def _enroll(
        self, csr: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """Enroll certificate via CES."""
        self.logger.debug("CAhandler._enroll()")
        if self.enrollment_config_log:
            enrollment_config_log(
                self.logger,
                self,
                list(self.enrollment_config_log_skip_list)
                + [
                    "ces_password",
                    "password",
                    "krb5_keytab",
                    "krb5_cache",
                    "krb5_config",
                    "krb5_kinit_path",
                    "_gssapi_creds",
                ],
            )

        template_error = self._ca_templates_membership_check()
        if template_error:
            return (template_error, None, None, None)

        try:
            result = self._wstep_issue(csr)
            return self._result_from_wstep(result)
        except Exception as err:
            self.logger.error("Failed to enroll certificate from CES: %s", err)
            return (self.CERT_FETCH_ERROR, None, None, None)

    def enroll(
        self, csr: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """Enroll certificate via MS-WSTEP."""
        self.logger.debug("CAhandler.enroll(%s)", self.template)
        self._gssapi_creds = None

        if not (self.ces_url and self._credentials_are_configured() and self.template):
            self.logger.error("%s", CONFIGURATION_ERROR_DETAIL)
            return (CONFIGURATION_ERROR_DETAIL, None, None, None)

        https_error = self._https_url_check(self.ces_url, "ces_url")
        if https_error:
            return (https_error, None, None, None)
        https_error = self._https_url_check(self.cep_url, "cep_url")
        if https_error:
            return (https_error, None, None, None)

        kerberos_error = self._kerberos_prepare_gssapi_backend()
        if kerberos_error:
            self._kerberos_cleanup_temporary_ccache()
            return (kerberos_error, None, None, None)

        gssapi_creds, gssapi_creds_error = self._kerberos_bind_gssapi_creds()
        if gssapi_creds_error:
            return (gssapi_creds_error, None, None, None)
        self._gssapi_creds = gssapi_creds

        error = eab_profile_header_info_check(
            self.logger, self, csr, self.profile_mapping_field
        )
        if error:
            self._kerberos_cleanup_temporary_ccache()
            return (error, None, None, None)

        error = self._allowed_templates_check()
        if error:
            self._kerberos_cleanup_temporary_ccache()
            return (error, None, None, None)

        with self._kerberos_runtime_environment():
            error, cert_bundle, cert_raw, poll_identifier = self._enroll(csr)

        self._kerberos_cleanup_temporary_ccache()
        self.logger.debug("Certificate.enroll() ended")
        return (error, cert_bundle, cert_raw, poll_identifier)

    def handler_check(self) -> Optional[str]:
        """Check that required config is present and CEP/CES URLs use HTTPS."""
        self.logger.debug("CAhandler.handler_check()")
        if not self.ces_url:
            error = "ces_url parameter is missing in config file"
            self.logger.error("%s: %s", CONFIGURATION_ERROR_DETAIL, error)
            return error

        required = [self.profile_mapping_field]
        if not (self.auth_method == "gssapi" and self._kerberos_keytab_is_configured()):
            required.extend(["ces_username", "ces_password"])
        error = handler_config_check(self.logger, self, required)
        if not error:
            error = self._https_url_check(self.ces_url, "ces_url")
        if not error:
            error = self._https_url_check(self.cep_url, "cep_url")
        self.logger.debug("CAhandler.handler_check() ended with %s", error)
        return error

    def poll(
        self, _cert_name: str, poll_identifier: str, _csr: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str], bool]:
        """Poll status of pending CSR and download certificates."""
        self.logger.debug("CAhandler.poll(%s)", poll_identifier)
        rejected = False
        request_id, reference = _poll_identifier_decode(poll_identifier)
        if not request_id:
            return ("Invalid poll identifier", None, None, poll_identifier, False)

        ces_url = reference or self.ces_url
        if not ces_url:
            return ("CES URL missing for poll", None, None, poll_identifier, False)

        https_error = self._https_url_check(ces_url, "ces_url")
        if https_error:
            return (https_error, None, None, poll_identifier, False)

        kerberos_error = self._kerberos_prepare_gssapi_backend()
        if kerberos_error:
            self._kerberos_cleanup_temporary_ccache()
            return (kerberos_error, None, None, poll_identifier, False)

        gssapi_creds, gssapi_creds_error = self._kerberos_bind_gssapi_creds()
        if gssapi_creds_error:
            return (gssapi_creds_error, None, None, poll_identifier, False)
        self._gssapi_creds = gssapi_creds

        try:
            with self._kerberos_runtime_environment():
                result = self._wstep_poll(request_id, ces_url)
            error, cert_bundle, cert_raw, new_poll_id = self._result_from_wstep(result)
            if result.get("status") == "denied":
                rejected = True
            if new_poll_id:
                poll_identifier = new_poll_id
            self._kerberos_cleanup_temporary_ccache()
            return (error, cert_bundle, cert_raw, poll_identifier, rejected)
        except Exception as err:
            self.logger.error("Failed to poll certificate from CES: %s", err)
            self._kerberos_cleanup_temporary_ccache()
            return (self.CERT_FETCH_ERROR, None, None, poll_identifier, False)

    def revoke(
        self, _cert: str, _rev_reason: str, _rev_date: str
    ) -> Tuple[int, str, str]:
        """Revoke certificate (not supported by CEP/CES)."""
        return (
            500,
            "urn:ietf:params:acme:error:serverInternal",
            "Revocation is not supported.",
        )

    def trigger(self, _payload: str) -> Tuple[str, str, str]:
        """Process trigger message (not supported)."""
        return ("Method not implemented.", None, None)
