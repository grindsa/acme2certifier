"""
DNS Persist Challenge Validator.

Implements validation logic for dns-persist-01 challenges according to
current ACME dns-persist draft behavior.
"""
import re
from typing import Optional, Set, Tuple
from .base import ChallengeValidator, ChallengeContext, ValidationResult


class DnsPersistChallengeValidator(ChallengeValidator):
    """Validator for dns-persist-01 challenges."""

    _DNS_RECORD_LABEL = "_validation-persist"

    _MALFORMED_ERROR = (
        '{"status": 400, "type": "urn:ietf:params:acme:error:malformed", '
        '"detail": "Malformed dns-persist-01 DNS TXT record"}'
    )
    _UNAUTHORIZED_ERROR = (
        '{"status": 403, "type": "urn:ietf:params:acme:error:unauthorized", '
        '"detail": "dns-persist-01 DNS TXT record did not authorize this request"}'
    )
    _INTERNAL_ERROR = (
        '{"status": 500, "type": "urn:ietf:params:acme:error:serverInternal", '
        '"detail": "dns-persist-01 validation temporarily unavailable"}'
    )

    def get_challenge_type(self) -> str:
        return "dns-persist-01"

    def perform_validation(self, context: ChallengeContext) -> ValidationResult:
        """Perform dns-persist-01 challenge validation."""
        self.logger.debug("DnsPersistChallengeValidator.perform_validation()")

        try:
            from acme_srv.helper import txt_get, uts_now
        except ImportError as err:
            self.logger.error(
                "DnsPersistChallengeValidator dependencies unavailable: %s", err
            )
            return ValidationResult(
                success=False,
                invalid=True,
                error_message=self._INTERNAL_ERROR,
                details={"reason": "validator_dependency_missing"},
            )

        context_check = self._validate_context(context)
        if context_check:
            return context_check

        accounturi = (context.options or {}).get("accounturi")
        normalized_issuers = self._normalized_issuer_names(context)
        allow_policy_wildcard = bool(
            (context.options or {}).get("allow_policy_wildcard", False)
        )
        wildcard_request = context.authorization_value.startswith("*.")

        fqdn = self._normalize_fqdn_for_dns_query(
            self._handle_wildcard_domain(context.authorization_value)
        )
        if not fqdn:
            return ValidationResult(
                success=False,
                invalid=True,
                error_message=self._MALFORMED_ERROR,
                details={"reason": "Invalid DNS authorization value"},
            )
        dns_record_name = f"{self._DNS_RECORD_LABEL}.{fqdn}"

        txt_records = txt_get(self.logger, dns_record_name, context.dns_servers)

        malformed_any = False
        for record in txt_records:
            verdict, record_malformed = self._evaluate_record(
                record,
                accounturi,
                normalized_issuers,
                wildcard_request,
                allow_policy_wildcard,
                uts_now,
            )
            malformed_any = malformed_any or record_malformed
            if verdict:
                verdict.details = {
                    "dns_record": dns_record_name,
                    **(verdict.details or {}),
                }
                return verdict

        if malformed_any:
            return ValidationResult(
                success=False,
                invalid=True,
                error_message=self._MALFORMED_ERROR,
                details={"dns_record": dns_record_name, "found_records": txt_records},
            )

        return ValidationResult(
            success=False,
            invalid=True,
            error_message=self._UNAUTHORIZED_ERROR,
            details={"dns_record": dns_record_name, "found_records": txt_records},
        )

    def _validate_context(self, context: ChallengeContext) -> Optional[ValidationResult]:
        """Validate challenge context preconditions."""
        if context.authorization_type and context.authorization_type.lower() != "dns":
            return ValidationResult(
                success=False,
                invalid=True,
                error_message=self._UNAUTHORIZED_ERROR,
                details={"reason": "dns-persist-01 only supports DNS identifiers"},
            )

        if not (context.options or {}).get("accounturi") or not self._normalized_issuer_names(
            context
        ):
            return ValidationResult(
                success=False,
                invalid=True,
                error_message=self._MALFORMED_ERROR,
                details={
                    "reason": "Missing accounturi or issuer-domain-names in challenge context"
                },
            )

        return None

    def _normalized_issuer_names(self, context: ChallengeContext) -> Set[str]:
        self.logger.debug("DnsPersistChallengeValidator._normalized_issuer_names()")
        issuer_domain_names = (context.options or {}).get("issuer_domain_names") or []
        return {issuer.strip().lower() for issuer in issuer_domain_names}

    def _evaluate_record(
        self,
        record: str,
        accounturi: str,
        normalized_issuers: Set[str],
        wildcard_request: bool,
        allow_policy_wildcard: bool,
        uts_now,
    ) -> Tuple[Optional[ValidationResult], bool]:
        """Evaluate one TXT record and return validation verdict."""
        self.logger.debug("DnsPersistChallengeValidator._evaluate_record() for record: %s", record)
        parsed = self._parse_issue_value(record)
        if parsed.get("malformed"):
            self.logger.debug("DnsPersistChallengeValidator._evaluate_record(): Record is malformed: %s", record)
            return None, True

        issuer = parsed.get("issuer_domain_name", "").lower()
        if issuer not in normalized_issuers:
            self.logger.debug("DnsPersistChallengeValidator._evaluate_record(): Issuer '%s' not in normalized issuers: %s", issuer, normalized_issuers)
            return None, False

        params = parsed.get("params", {})
        if "accounturi" not in params:
            self.logger.debug("DnsPersistChallengeValidator._evaluate_record(): Missing accounturi parameter in record: %s", record)
            return None, True
        if params["accounturi"] != accounturi:
            self.logger.debug("DnsPersistChallengeValidator._evaluate_record(): Account URI mismatch. Expected: %s, Found: %s", accounturi, params["accounturi"])
            return None, False

        persist_until = params.get("persistuntil")
        if persist_until and not re.fullmatch(r"\d+", persist_until):
            self.logger.debug("DnsPersistChallengeValidator._evaluate_record(): Invalid persistuntil value (not an integer): %s", persist_until)
            return None, True
        if persist_until and int(persist_until) < uts_now():
            self.logger.debug("DnsPersistChallengeValidator._evaluate_record(): persistuntil timestamp is in the past: %s", persist_until)
            return None, False

        if wildcard_request:
            if not allow_policy_wildcard:
                self.logger.error(
                    "Wildcard authorization requested for but policy wildcard support is disabled",
                )
                return None, False

            policy = params.get("policy", "")
            if policy.lower() != "wildcard":
                self.logger.debug(
                    "DnsPersistChallengeValidator._evaluate_record(): wildcard authorization requested but policy is not wildcard: %s",
                    policy,
                )
                return None, False

        return (
            ValidationResult(
                success=True,
                invalid=False,
                details={
                    "matched_issuer": issuer,
                    "matched_accounturi": accounturi,
                },
            ),
            False,
        )

    def _parse_issue_value(self, record):
        """Parse issue-value style TXT record content."""
        self.logger.debug("DnsPersistChallengeValidator._parse_issue_value() for record: %s", record)

        # dnspython TXT records are often returned as bytes.
        if isinstance(record, bytes):
            value = record.decode("utf-8", errors="replace")
        elif record is None:
            value = ""
        else:
            value = str(record)

        value = value.strip().strip('"')
        if not value:
            return {"malformed": True}

        parts = [part.strip() for part in value.split(";")]
        issuer = parts[0]
        if not issuer or "=" in issuer:
            self.logger.debug("DnsPersistChallengeValidator._parse_issue_value(): Missing or invalid issuer in record: %s", record)
            return {"malformed": True}

        params = {}
        for part in parts[1:]:
            if not part:
                continue
            if "=" not in part:
                self.logger.debug("DnsPersistChallengeValidator._parse_issue_value(): Missing '=' in parameter part: %s", part)
                return {"malformed": True}
            key, val = part.split("=", 1)
            key = key.strip().lower()
            val = val.strip()
            if not key:
                self.logger.debug("DnsPersistChallengeValidator._parse_issue_value(): Missing key in parameter part: %s", part)
                return {"malformed": True}
            if key in params:
                self.logger.debug("DnsPersistChallengeValidator._parse_issue_value(): Duplicate key in parameter part: %s", part)
                return {"malformed": True}
            params[key] = val

        self.logger.debug("DnsPersistChallengeValidator._parse_issue_value(): Parsed record with issuer: %s and params: %s", issuer, params)
        return {
            "malformed": False,
            "issuer_domain_name": issuer,
            "params": params,
        }

    def _handle_wildcard_domain(self, fqdn: str) -> str:
        """Handle wildcard domain by removing the '*.' prefix."""
        self.logger.debug("DnsPersistChallengeValidator._handle_wildcard_domain() for fqdn: %s", fqdn)
        if fqdn.startswith("*."):
            self.logger.debug("DnsPersistChallengeValidator._handle_wildcard_domain(): Detected wildcard domain, stripping '*.' prefix")
            return fqdn[2:]
        return fqdn

    def _normalize_fqdn_for_dns_query(self, fqdn: str) -> str:
        """Normalize and minimally validate DNS name used in TXT queries."""
        if fqdn is None:
            return ""
        normalized = str(fqdn).strip().rstrip(".").lower()
        if (
            not normalized
            or " " in normalized
            or normalized.startswith(".")
            or ".." in normalized
            or not re.fullmatch(r"[a-z0-9.-]+", normalized)
        ):
            return ""
        return normalized
