"""trigger class"""

# pylint: disable=c0209
from __future__ import print_function
import json
from typing import Any, Dict, List, Optional, Tuple
from acme2certifier.acme_srv.certificate import Certificate
from acme2certifier.acme_srv.db_handler import DBstore
from acme2certifier.acme_srv.helper import (
    convert_byte_to_string,
    convert_string_to_byte,
    cert_pubkey_get,
    csr_pubkey_get,
    cert_der2pem,
    b64_decode,
    load_config,
    ca_handler_load,
)
from acme2certifier.acme_srv.helpers.global_variables import DB_ERROR_MSG
from acme2certifier.acme_srv.helpers.trigger_auth import (
    TRIGGER_SIGNATURE_HEADER,
    trigger_ca_cert_load,
    trigger_cert_chain_verify,
    trigger_hmac_keys_load,
    trigger_hmac_verify,
    trigger_signature_from_headers,
)

_PARSE_RETURNS_MSG = "Trigger.parse() returns: %s"


def trigger_config_enabled(config_dic) -> bool:
    """Return True when [Trigger] enabled is set in acme_srv.cfg."""
    getboolean = getattr(config_dic, "getboolean", None)
    if callable(getboolean):
        return bool(getboolean("Trigger", "enabled", fallback=False))
    # Defensive: empty/malformed mocks used in some unit tests
    section = config_dic.get("Trigger") if hasattr(config_dic, "get") else None
    if isinstance(section, dict):
        value = str(section.get("enabled", "False")).strip().lower()
        return value in {"1", "true", "yes", "on"}
    return False


def handler_supports_trigger(cahandler_cls) -> bool:
    """Return True when the CA handler class opts into trigger support."""
    return bool(getattr(cahandler_cls, "supports_trigger", False))


def _cahandler_class_load(logger, config_dic):
    """Load CAhandler class from the configured CA handler module."""
    ca_handler_module = ca_handler_load(logger, config_dic)
    if ca_handler_module is None:
        return None
    return getattr(ca_handler_module, "CAhandler", None)


def _trigger_status_log(
    logger, log_status: bool, level: str, message: str, *args
) -> None:
    """Emit a trigger-enablement status log when requested."""
    if log_status:
        getattr(logger, level)(message, *args)


def resolve_trigger_endpoint(logger, config_dic, *, log_status: bool = False) -> bool:
    """
    Decide whether the /trigger HTTP endpoint should be active.

    Requires [Trigger] enabled=True, CAhandler.supports_trigger=True,
    a readable ca_cert, and either hmac_keys or gated auth_disable.
    Missing supports_trigger defaults to False. Does not raise on misconfig.
    """
    if not trigger_config_enabled(config_dic):
        return False

    cahandler_cls = _cahandler_class_load(logger, config_dic)
    if cahandler_cls is None:
        _trigger_status_log(
            logger,
            log_status,
            "warning",
            "Trigger enabled in config but CA handler could not be loaded; "
            "leaving /trigger disabled",
        )
        return False

    if not handler_supports_trigger(cahandler_cls):
        _trigger_status_log(
            logger,
            log_status,
            "warning",
            "Trigger enabled in config but CA handler %s does not set "
            "supports_trigger=True; leaving /trigger disabled",
            getattr(cahandler_cls, "__module__", cahandler_cls),
        )
        return False

    hmac_keys, auth_disabled = trigger_hmac_keys_load(logger, config_dic)
    ca_cert = trigger_ca_cert_load(logger, config_dic)
    if not ca_cert:
        _trigger_status_log(
            logger,
            log_status,
            "error",
            "Trigger enabled but [Trigger] ca_cert is missing or unreadable; "
            "leaving /trigger disabled",
        )
        return False
    if not hmac_keys and not auth_disabled:
        _trigger_status_log(
            logger,
            log_status,
            "error",
            "Trigger enabled but no hmac_keys/hmac_keys_file configured "
            "(and auth_disable is not acknowledged); leaving /trigger disabled",
        )
        return False

    _trigger_status_log(logger, log_status, "info", "Trigger HTTP endpoint enabled")
    return True


class Trigger(object):
    """Challenge handler"""

    def __init__(
        self, debug: bool = False, srv_name: str = None, logger: object = None
    ):
        self.debug = debug
        self.server_name = srv_name
        self.cahandler = None
        self.logger = logger
        self.dbstore = DBstore(debug, self.logger)
        self.tnauthlist_support = False
        self.enabled = False
        self.hmac_keys: List[str] = []
        self.auth_disabled = False
        self.ca_cert: Optional[str] = None

    def __enter__(self):
        """Makes ACMEHandler a Context Manager"""
        self._config_load()
        return self

    def __exit__(self, *args):
        """close the connection at the end of the context"""

    def _certname_lookup(self, cert_pem: str) -> List[str]:
        """compared certificate against csr stored in db"""
        self.logger.debug("Trigger._certname_lookup()")

        result_list = []
        # extract the public key form certificate
        cert_pubkey = cert_pubkey_get(self.logger, cert_pem)
        with Certificate(self.debug, "foo", self.logger) as certificate:
            # search certificates in status "processing"
            cert_list = certificate.certlist_search(
                "order__status_id", 4, ["name", "csr", "order__name"]
            )

            for cert in cert_list:
                # extract public key from certificate and compare it with pub from cert
                if "csr" in cert and cert["csr"]:
                    csr_pubkey = csr_pubkey_get(self.logger, cert["csr"])
                    if csr_pubkey == cert_pubkey:
                        result_list.append(
                            {
                                "cert_name": cert["name"],
                                "order_name": cert["order__name"],
                            }
                        )
        self.logger.debug("Trigger._certname_lookup() ended with: %s", result_list)

        return result_list

    def _config_load(self):
        """ " load config from file"""
        self.logger.debug("Certificate._config_load()")
        config_dic = load_config()
        if "Order" in config_dic:
            self.tnauthlist_support = config_dic.getboolean(
                "Order", "tnauthlist_support", fallback=False
            )

        ca_handler_module = ca_handler_load(self.logger, config_dic)
        if ca_handler_module:
            # store handler in variable
            try:
                self.cahandler = ca_handler_module.CAhandler
            except Exception as err_:
                self.logger.critical(
                    "Failed to load CA handler module: %s",
                    err_,
                )

        self.hmac_keys, self.auth_disabled = trigger_hmac_keys_load(
            self.logger, config_dic
        )
        self.ca_cert = trigger_ca_cert_load(self.logger, config_dic)
        self.enabled = resolve_trigger_endpoint(
            self.logger, config_dic, log_status=False
        )
        self.logger.debug("ca_handler: %s", ca_handler_module)
        self.logger.debug("Certificate._config_load() ended.")

    def _certificate_record_add(
        self, cert_bundle: str, cert_name: str, cert_raw: str
    ) -> None:
        """Persist certificate bundle for a processing order."""
        try:
            self.dbstore.certificate_add(
                {"cert": cert_bundle, "name": cert_name, "cert_raw": cert_raw}
            )
        except Exception as err_:
            self.logger.critical(
                f"{DB_ERROR_MSG}: failed to add certificate during trigger processing: %s",
                err_,
            )

    def _order_status_valid_set(self, order_name: str) -> None:
        """Mark the matching order as valid after certificate store."""
        try:
            self.dbstore.order_update({"name": order_name, "status": "valid"})
        except Exception as err_:
            self.logger.critical(
                f"{DB_ERROR_MSG}: failed to update order status during trigger processing: %s",
                err_,
            )

    def _matched_certificates_store(
        self, cert_name_list: List[Dict[str, str]], cert_bundle: str, cert_raw: str
    ) -> None:
        """Store certificates and mark related orders valid."""
        for cert in cert_name_list:
            self._certificate_record_add(cert_bundle, cert["cert_name"], cert_raw)
            order_name = cert.get("order_name")
            if order_name:
                self._order_status_valid_set(order_name)

    def _cert_store(
        self, cert_bundle: str, cert_raw: str, cert_pem: str
    ) -> Tuple[int, str, str]:
        """store certificate"""
        self.logger.debug("Trigger._cert_store()")

        if not self.ca_cert:
            self.logger.error("Trigger ca_cert not configured")
            return (400, "certificate verification failed", None)

        if not trigger_cert_chain_verify(
            self.logger, cert_pem, cert_bundle, self.ca_cert
        ):
            self.logger.warning("submitted certificate failed ca_cert chain verify")
            return (400, "certificate verification failed", None)

        cert_name_list = self._certname_lookup(cert_pem)
        if len(cert_name_list) > 1:
            self.logger.warning(
                "ambiguous pubkey match for %s processing orders",
                len(cert_name_list),
            )
            return (409, "ambiguous certificate match", None)

        if not cert_name_list:
            self.logger.debug("Trigger._cert_store() ended")
            return (400, "certificate_name lookup failed", None)

        self._matched_certificates_store(cert_name_list, cert_bundle, cert_raw)
        self.logger.debug("Trigger._cert_store() ended")
        return (200, "OK", None)

    def _payload_process(self, payload: str) -> Tuple[int, str, str]:
        """process payload"""
        self.logger.debug("Trigger._payload_process()")
        with self.cahandler(self.debug, self.logger) as ca_handler:
            if payload:
                error, cert_bundle, cert_raw = ca_handler.trigger(payload)
                if cert_bundle and cert_raw:
                    # returned cert_raw is in dear format, convert to pem for pubkey/chain checks
                    cert_pem = convert_byte_to_string(
                        cert_der2pem(b64_decode(self.logger, cert_raw))
                    )
                    # store certificate and create responses
                    code, message, detail = self._cert_store(
                        cert_bundle, cert_raw, cert_pem
                    )
                else:
                    code = 400
                    message = error
                    detail = None
            else:
                code = 400
                message = "payload malformed"
                detail = None

        self.logger.debug("Trigger._payload_process() ended with: %s %s", code, message)
        return (code, message, detail)

    def _auth_check(self, raw_body: bytes, headers: Optional[Dict[str, Any]]) -> bool:
        """Return True when the request passes trigger HMAC authentication."""
        if self.auth_disabled:
            return True
        signature = trigger_signature_from_headers(headers)
        if trigger_hmac_verify(raw_body, signature, self.hmac_keys):
            return True
        self.logger.warning(
            "Trigger authentication failed (missing/invalid %s)",
            TRIGGER_SIGNATURE_HEADER,
        )
        return False

    def parse(
        self, content: Any, headers: Optional[Dict[str, Any]] = None
    ) -> Dict[str, str]:
        """new oder request"""
        self.logger.debug("Trigger.parse()")

        if not self.enabled:
            self.logger.warning(
                "Trigger endpoint disabled; set [Trigger] enabled=True, "
                "hmac_keys (or gated auth_disable), ca_cert, and use a CA handler "
                "with supports_trigger=True"
            )
            response_dic = {
                "header": {},
                "code": 403,
                "data": {
                    "status": 403,
                    "type": "unauthorized",
                    "detail": "trigger endpoint disabled",
                },
            }
            self.logger.debug(_PARSE_RETURNS_MSG, json.dumps(response_dic))
            return response_dic

        if isinstance(content, (bytes, bytearray)):
            raw_body = bytes(content)
        else:
            raw_body = convert_string_to_byte(content if content is not None else "")

        if not self._auth_check(raw_body, headers):
            response_dic = {
                "header": {},
                "code": 403,
                "data": {
                    "status": 403,
                    "type": "unauthorized",
                    "detail": "trigger authentication failed",
                },
            }
            self.logger.debug(_PARSE_RETURNS_MSG, json.dumps(response_dic))
            return response_dic

        # convert to json structure
        try:
            payload = json.loads(convert_byte_to_string(raw_body))
        except Exception:
            payload = {}

        if "payload" in payload:
            if payload["payload"]:
                code, message, detail = self._payload_process(payload["payload"])
            else:
                code = 400
                message = "malformed"
                detail = "payload empty"
        else:
            code = 400
            message = "malformed"
            detail = "payload missing"
        response_dic = {}

        # prepare/enrich response
        response_dic["header"] = {}
        response_dic["code"] = code
        response_dic["data"] = {"status": code, "type": message}
        if detail:
            response_dic["data"]["detail"] = detail

        self.logger.debug(_PARSE_RETURNS_MSG, json.dumps(response_dic))
        return response_dic
