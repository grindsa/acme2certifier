# -*- coding: utf-8 -*-
"""Tests for acme_srv.helpers.crypto."""

from __future__ import annotations

import logging
import sys
from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from acme2certifier.acme_srv.helpers.crypto import (
    akp_jwk_supported,
    decode_deserialize,
    decode_message,
    generate_random_string,
    jwk_thumbprint_get,
    sha256_hash,
    sha256_hash_hex,
    signature_check,
    string_sanitize,
    unsupported_jwk_detail,
)
from acme2certifier.acme_srv.helpers.encoding import b64_url_encode

pytestmark = pytest.mark.usefixtures("clear_config_cache", "_silence_logging")


class TestCrypto:
    """Central tests for crypto helpers."""

    def test_001_decode_deserialize_success(self, logger: logging.Logger) -> None:
        """test successful deserialization of a b64 encoded string"""
        assert {"a": "b", "c": "d"} == decode_deserialize(
            logger, "eyJhIiA6ICJiIiwgImMiIDogImQifQ=="
        )

    def test_002_decode_deserialize_failure(self, logger: logging.Logger) -> None:
        """test failed deserialization of a b64 encoded string"""
        assert "ERR: Json decoding error" == decode_deserialize(
            logger, "Zm9vLXdoaWNoLWNhbm5vdC1iZS1qc29uaXplZA=="
        )

    def test_003_signature_check_success(self, logger: logging.Logger) -> None:
        """successful validation of signature"""
        mkey = {
            "alg": "RS256",
            "e": "AQAB",
            "kty": "RSA",
            "n": "2CFMV4MK6Uo_2GQWa0KVWlzffgSDiLwur4ujSZkCRzbA3w5p1ABJgr7l_P84HpRv8R8rGL67hqmDJuT52mGD6fMVAhHPX5pSdtyZlQQuzpXonzNmHbG1DbMSiXrxg5jWVXchCxHx82wAt9Kf13O5ATxD0WOBB5FffpqQHh8zTf29jTL4vBd8N57ce17ZgNWl_EcoByjigqNFJcO0rrvrf6xyNaO9nbun4PAMJTLbfVa6CiEqjnjYMX80VYLH4fCqsAZgxIoli_D2j9P5Kq6KZZUL_bZ2QQV4UuwWZvh6tcA393YQLeMARnhWI6dqlZVdcU74NXi9NhSxcMkM8nZZ8Q",
        }
        message = '{"protected": "eyJub25jZSI6ICI3N2M3MmViMDE5NDc0YzBjOWIzODk5MmU4ZjRkMDIzYSIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIn0","payload": "eyJzdGF0dXMiOiJkZWFjdGl2YXRlZCJ9","signature": "QYbMYZ1Dk8dHKqOwWBQHvWdnGD7donGZObb2Ry_Y5PsHpcTrj8Y2CM57SNVAR9V0ePg4vhK3-IbwYAKbhZV8jF7E-ylZaYm4PSQcumKLI55qvDiEvDiZ0gmjf_GAcsC40TwBa11lzR1u0dQYxOlQ_y9ak6705c5bM_V4_ttQeslJXCfVIQoV-sZS0Z6tJfy5dPVDR7JYG77bZbD3K-HCCaVbT7ilqcf00rA16lvw13zZnIgbcZsbW-eJ2BM_QxE24PGqc_vMfAxIiUG0VY7DqrKumLs91lHHTEie8I-CapH6AetsBhGtRcB6EL_Rn6qGQZK9YBpvoXANv_qF2-zQkQ"}'
        assert (True, None) == signature_check(logger, message, mkey)

    def test_004_signature_check_wrong_key(self, logger: logging.Logger) -> None:
        """failed validation of signature wrong key"""
        mkey = {
            "alg": "rs256",
            "e": "AQAB",
            "kty": "RSA",
            "n": "zncgRHCp22-29g9FO4Hn02iyS1Fo4Y1tB-6cucH1yKSxM6bowjAaVa4HkAnIxgF6Zj9qLROgQR84YjMPeNkq8woBRz1aziDiTIOc0D2aXvLgZbuFGesvxoSGd6uyxjyyV7ONwZEpB8QtDW0I3shlhosKB3Ni1NFu55bPUP9RvxUdPzRRuhxUMHc1CXre1KR0eQmQdNZT6tgQVxpv2lb-iburBADjivBRyrI3k3NmXkYknBggAu8JInaFY4T8pVK0jTwP-f3-0eAV1bg99Rm7uXNXl7SKpQ3oGihwy2OK-XAc59v6C3n4Wq9QpzGkFWsOOlp4zEf13L3_UKugeExEqw",
        }
        message = '{"protected": "eyJub25jZSI6ICI3N2M3MmViMDE5NDc0YzBjOWIzODk5MmU4ZjRkMDIzYSIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIn0","payload": "eyJzdGF0dXMiOiJkZWFjdGl2YXRlZCJ9","signature": "QYbMYZ1Dk8dHKqOwWBQHvWdnGD7donGZObb2Ry_Y5PsHpcTrj8Y2CM57SNVAR9V0ePg4vhK3-IbwYAKbhZV8jF7E-ylZaYm4PSQcumKLI55qvDiEvDiZ0gmjf_GAcsC40TwBa11lzR1u0dQYxOlQ_y9ak6705c5bM_V4_ttQeslJXCfVIQoV-sZS0Z6tJfy5dPVDR7JYG77bZbD3K-HCCaVbT7ilqcf00rA16lvw13zZnIgbcZsbW-eJ2BM_QxE24PGqc_vMfAxIiUG0VY7DqrKumLs91lHHTEie8I-CapH6AetsBhGtRcB6EL_Rn6qGQZK9YBpvoXANv_qF2-zQkQ"}'
        if int("%i%i" % (sys.version_info[0], sys.version_info[1])) <= 36:
            result = (
                False,
                "Verification failed for all signatures[\"Failed: [InvalidJWSSignature('Verification failed',)]\"]",
            )
        else:
            result = (
                False,
                "Verification failed for all signatures[\"Failed: [InvalidJWSSignature('Verification failed')]\"]",
            )
        assert result == signature_check(logger, message, mkey)

    def test_005_signature_check_faulty_key(self, logger: logging.Logger) -> None:
        """failed validation of signature faulty key"""
        mkey = {
            "alg": "rs256",
            "e": "AQAB",
            "n": "zncgRHCp22-29g9FO4Hn02iyS1Fo4Y1tB-6cucH1yKSxM6bowjAaVa4HkAnIxgF6Zj9qLROgQR84YjMPeNkq8woBRz1aziDiTIOc0D2aXvLgZbuFGesvxoSGd6uyxjyyV7ONwZEpB8QtDW0I3shlhosKB3Ni1NFu55bPUP9RvxUdPzRRuhxUMHc1CXre1KR0eQmQdNZT6tgQVxpv2lb-iburBADjivBRyrI3k3NmXkYknBggAu8JInaFY4T8pVK0jTwP-f3-0eAV1bg99Rm7uXNXl7SKpQ3oGihwy2OK-XAc59v6C3n4Wq9QpzGkFWsOOlp4zEf13L3_UKugeExEqw",
        }
        message = '{"protected": "eyJub25jZSI6ICI3N2M3MmViMDE5NDc0YzBjOWIzODk5MmU4ZjRkMDIzYSIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIn0","payload": "eyJzdGF0dXMiOiJkZWFjdGl2YXRlZCJ9","signature": "QYbMYZ1Dk8dHKqOwWBQHvWdnGD7donGZObb2Ry_Y5PsHpcTrj8Y2CM57SNVAR9V0ePg4vhK3-IbwYAKbhZV8jF7E-ylZaYm4PSQcumKLI55qvDiEvDiZ0gmjf_GAcsC40TwBa11lzR1u0dQYxOlQ_y9ak6705c5bM_V4_ttQeslJXCfVIQoV-sZS0Z6tJfy5dPVDR7JYG77bZbD3K-HCCaVbT7ilqcf00rA16lvw13zZnIgbcZsbW-eJ2BM_QxE24PGqc_vMfAxIiUG0VY7DqrKumLs91lHHTEie8I-CapH6AetsBhGtRcB6EL_Rn6qGQZK9YBpvoXANv_qF2-zQkQ"}'
        ok, detail = signature_check(logger, message, mkey)
        assert not ok
        assert detail.startswith('Unknown type "None", valid types are:'), detail

    def test_006_signature_check_no_key(self, logger: logging.Logger) -> None:
        """failed validation of signature no key"""
        mkey = {}
        message = '{"protected": "eyJub25jZSI6ICI3N2M3MmViMDE5NDc0YzBjOWIzODk5MmU4ZjRkMDIzYSIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIn0","payload": "eyJzdGF0dXMiOiJkZWFjdGl2YXRlZCJ9","signature": "QYbMYZ1Dk8dHKqOwWBQHvWdnGD7donGZObb2Ry_Y5PsHpcTrj8Y2CM57SNVAR9V0ePg4vhK3-IbwYAKbhZV8jF7E-ylZaYm4PSQcumKLI55qvDiEvDiZ0gmjf_GAcsC40TwBa11lzR1u0dQYxOlQ_y9ak6705c5bM_V4_ttQeslJXCfVIQoV-sZS0Z6tJfy5dPVDR7JYG77bZbD3K-HCCaVbT7ilqcf00rA16lvw13zZnIgbcZsbW-eJ2BM_QxE24PGqc_vMfAxIiUG0VY7DqrKumLs91lHHTEie8I-CapH6AetsBhGtRcB6EL_Rn6qGQZK9YBpvoXANv_qF2-zQkQ"}'
        assert (False, "No key specified.") == signature_check(logger, message, mkey)

    def test_007_generate_random_string_len_5(self, logger: logging.Logger) -> None:
        """generate_random_string length 5"""
        assert 5 == len(generate_random_string(logger, 5))

    def test_008_generate_random_string_len_15(self, logger: logging.Logger) -> None:
        """generate_random_string length 15"""
        assert 15 == len(generate_random_string(logger, 15))

    def test_009_decode_message_empty_payload(self, logger: logging.Logger) -> None:
        """decode message with empty payload - certbot issue"""
        data_dic = '{"protected": "eyJub25jZSI6ICIyNmU2YTQ2ZWZhZGQ0NzdkOTA4ZDdjMjAxNGU0OWIzNCIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYXV0aHovUEcxODlGRnpmYW8xIiwgImtpZCI6ICJodHRwOi8vbGFwdG9wLm5jbG0tc2FtYmEubG9jYWwvYWNtZS9hY2N0L3l1WjFHVUpiNzZaayIsICJhbGciOiAiUlMyNTYifQ", "payload": "", "signature": "ZW5jb2RlZF9zaWduYXR1cmU="}'
        e_result = (
            True,
            None,
            {
                "nonce": "26e6a46efadd477d908d7c2014e49b34",
                "url": "http://laptop.nclm-samba.local/acme/authz/PG189FFzfao1",
                "alg": "RS256",
                "kid": "http://laptop.nclm-samba.local/acme/acct/yuZ1GUJb76Zk",
            },
            {},
            b"encoded_signature",
        )
        assert e_result == decode_message(logger, data_dic)

    def test_010_decode_message_with_payload(self, logger: logging.Logger) -> None:
        """decode message with JSON payload"""
        data_dic = '{"protected": "eyJub25jZSI6ICIyNmU2YTQ2ZWZhZGQ0NzdkOTA4ZDdjMjAxNGU0OWIzNCIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYXV0aHovUEcxODlGRnpmYW8xIiwgImtpZCI6ICJodHRwOi8vbGFwdG9wLm5jbG0tc2FtYmEubG9jYWwvYWNtZS9hY2N0L3l1WjFHVUpiNzZaayIsICJhbGciOiAiUlMyNTYifQ", "payload": "eyJmb28iOiAiYmFyMSJ9", "signature": "ZW5jb2RlZF9zaWduYXR1cmU="}'
        e_result = (
            True,
            None,
            {
                "nonce": "26e6a46efadd477d908d7c2014e49b34",
                "url": "http://laptop.nclm-samba.local/acme/authz/PG189FFzfao1",
                "alg": "RS256",
                "kid": "http://laptop.nclm-samba.local/acme/acct/yuZ1GUJb76Zk",
            },
            {"foo": "bar1"},
            b"encoded_signature",
        )
        assert e_result == decode_message(logger, data_dic)

    @patch("json.loads")
    def test_011_decode_message_exception(
        self,
        mock_json: MagicMock,
        logger: logging.Logger,
        capture_logs: Callable[..., AbstractContextManager[Any]],
    ) -> None:
        """decode message with exception during decoding"""
        mock_json.side_effect = Exception("exc_mock_json")
        data_dic = '{"protected": "eyJub25jZSI6ICIyNmU2YTQ2ZWZhZGQ0NzdkOTA4ZDdjMjAxNGU0OWIzNCIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYXV0aHovUEcxODlGRnpmYW8xIiwgImtpZCI6ICJodHRwOi8vbGFwdG9wLm5jbG0tc2FtYmEubG9jYWwvYWNtZS9hY2N0L3l1WjFHVUpiNzZaayIsICJhbGciOiAiUlMyNTYifQ", "payload": "", "signature": "ZW5jb2RlZF9zaWduYXR1cmU="}'
        if int("%i%i" % (sys.version_info[0], sys.version_info[1])) < 37:
            result = "ERROR:test_a2c:Error during message decoding Invalid JWS Object [Invalid format]"
            e_result = (False, "Invalid JWS Object [Invalid format]", {}, {}, None)
        else:
            result = "ERROR:test_a2c:Error during message decoding Invalid JWS Object [Invalid format]"
            e_result = (False, "Invalid JWS Object [Invalid format]", {}, {}, None)
        with capture_logs("test_a2c", level="INFO") as lcm:
            assert e_result == decode_message(logger, data_dic)
        assert result in lcm.output

    def test_012_signature_check_symmetric_success(
        self, logger: logging.Logger
    ) -> None:
        """successful validation symmetric key"""
        mkey = '{"k": "ZndUSkZvVldvMEFiRzQ5VWNCdERtNkNBNnBTcTl4czNKVEVxdUZiaEdpZXZNUVJBVmRuSFREcDJYX2s3X0NxTA", "kty": "oct"}'
        message = '{"payload": "eyJlIjogIkFRQUIiLCAia3R5IjogIlJTQSIsICJuIjogIm5kN3ZWUTNraW4zS3BKdTd6RUZNTlVPb0ZIQmVDUWRFRTUyOF9iOHo2djNDNnYtQS0zeUdBcTFWTjZmRTluUXdYSmNlZ2ZNdm1MczlCVVllVjZ2M1FzdGhkVFRCdW5FS1l0TVVZUVRmNkpwaHNEb1pHTkt1dnpCY2ZxSlN2TXpCNHdwa3hORm1Pa2M1QVhwRzhnQWJiTTRuS3JDQkdCQ21lZ2RJUEc3U0g3Mk9tejN6YjIwemZfZlo4dHVoUzk1eUJKdndKRjhZRGtCdDViWUV5ZnQ4aVoyWVFGVmRZZW5FMDhKOGRBUGNVQy1HYld6NmJXUm9Xc0xOT21VNkVjSndsSV9tRXRqazA5aTNlVEhOa2Vna3NrZUJOeXhlSkdtaVRtMHRtS1MwOEVvY0VQTDA1UktxSm9XNnhVcHNITDcwSzdzUVRaUDBHSUY1VXBwSkZXMnlVdyJ9", "protected": "eyJ1cmwiOiAiaHR0cDovL2FjbWUtc3J2LmJhci5sb2NhbC9hY21lL25ld2FjY291bnQiLCAiYWxnIjogIkhTMjU2IiwgImtpZCI6ICJiYXIifQ", "signature": "VXYLfPuoClsn_rhPPV8qjspZV1Q7HyX8rXv6odWYnLI"}'
        assert (True, None) == signature_check(logger, message, mkey, json_=True)

    def test_013_signature_check_symmetric_wrong_key(
        self, logger: logging.Logger
    ) -> None:
        """failed validation wrong symmetric key"""
        mkey = '{"k": "ZndUSkZvVldvMEFiRzQ5VWNCdERtNkNBNnBTcTl4czNKVEVxdUZiaEdpZXZNUVJBVmRuSFREcDJYX2s3X0NxvA", "kty": "oct"}'
        message = '{"payload": "eyJlIjogIkFRQUIiLCAia3R5IjogIlJTQSIsICJuIjogIm5kN3ZWUTNraW4zS3BKdTd6RUZNTlVPb0ZIQmVDUWRFRTUyOF9iOHo2djNDNnYtQS0zeUdBcTFWTjZmRTluUXdYSmNlZ2ZNdm1MczlCVVllVjZ2M1FzdGhkVFRCdW5FS1l0TVVZUVRmNkpwaHNEb1pHTkt1dnpCY2ZxSlN2TXpCNHdwa3hORm1Pa2M1QVhwRzhnQWJiTTRuS3JDQkdCQ21lZ2RJUEc3U0g3Mk9tejN6YjIwemZfZlo4dHVoUzk1eUJKdndKRjhZRGtCdDViWUV5ZnQ4aVoyWVFGVmRZZW5FMDhKOGRBUGNVQy1HYld6NmJXUm9Xc0xOT21VNkVjSndsSV9tRXRqazA5aTNlVEhOa2Vna3NrZUJOeXhlSkdtaVRtMHRtS1MwOEVvY0VQTDA1UktxSm9XNnhVcHNITDcwSzdzUVRaUDBHSUY1VXBwSkZXMnlVdyJ9", "protected": "eyJ1cmwiOiAiaHR0cDovL2FjbWUtc3J2LmJhci5sb2NhbC9hY21lL25ld2FjY291bnQiLCAiYWxnIjogIkhTMjU2IiwgImtpZCI6ICJiYXIifQ", "signature": "VXYLfPuoClsn_rhPPV8qjspZV1Q7HyX8rXv6odWYnLI"}'
        if int("%i%i" % (sys.version_info[0], sys.version_info[1])) <= 36:
            error = "Verification failed for all signatures[\"Failed: [InvalidJWSSignature('Verification failed',)]\"]"
        else:
            error = "Verification failed for all signatures[\"Failed: [InvalidJWSSignature('Verification failed')]\"]"
        assert (False, error) == signature_check(logger, message, mkey, json_=True)

    def test_014_signature_check_symmetric_without_json_flag(
        self,
        logger: logging.Logger,
        capture_logs: Callable[..., AbstractContextManager[Any]],
    ) -> None:
        """failed validation wrong symmetric key without json_ flag set"""
        mkey = '{"k": "ZndUSkZvVldvMEFiRzQ5VWNCdERtNkNBNnBTcTl4czNKVEVxdUZiaEdpZXZNUVJBVmRuSFREcDJYX2s3X0NxvA", "kty": "oct"}'
        message = '{"payload": "eyJlIjogIkFRQUIiLCAia3R5IjogIlJTQSIsICJuIjogIm5kN3ZWUTNraW4zS3BKdTd6RUZNTlVPb0ZIQmVDUWRFRTUyOF9iOHo2djNDNnYtQS0zeUdBcTFWTjZmRTluUXdYSmNlZ2ZNdm1MczlCVVllVjZ2M1FzdGhkVFRCdW5FS1l0TVVZUVRmNkpwaHNEb1pHTkt1dnpCY2ZxSlN2TXpCNHdwa3hORm1Pa2M1QVhwRzhnQWJiTTRuS3JDQkdCQ21lZ2RJUEc3U0g3Mk9tejN6YjIwemZfZlo4dHVoUzk1eUJKdndKRjhZRGtCdDViWUV5ZnQ4aVoyWVFGVmRZZW5FMDhKOGRBUGNVQy1HYld6NmJXUm9Xc0xOT21VNkVjSndsSV9tRXRqazA5aTNlVEhOa2Vna3NrZUJOeXhlSkdtaVRtMHRtS1MwOEVvY0VQTDA1UktxSm9XNnhVcHNITDcwSzdzUVRaUDBHSUY1VXBwSkZXMnlVdyJ9", "protected": "eyJ1cmwiOiAiaHR0cDovL2FjbWUtc3J2LmJhci5sb2NhbC9hY21lL25ld2FjY291bnQiLCAiYWxnIjogIkhTMjU2IiwgImtpZCI6ICJiYXIifQ", "signature": "VXYLfPuoClsn_rhPPV8qjspZV1Q7HyX8rXv6odWYnLI"}'
        py_ver = sys.version_info[:2]
        if py_ver < (3, 9):
            error = "type object argument after ** must be a mapping, not str"
        elif py_ver >= (3, 15):
            error = "Value after ** must be a mapping, not str"
        else:
            error = "jwcrypto.jwk.JWK() argument after ** must be a mapping, not str"
        with capture_logs("test_a2c", level="INFO") as lcm:
            assert (False, error) == signature_check(logger, message, mkey)
        assert "ERROR:test_a2c:No jwkey extracted" in lcm.output

    def test_015_signature_check_invalid_key(self, logger: logging.Logger) -> None:
        """failed validation invalid key"""
        mkey = "invalid key"
        message = '{"payload": "eyJlIjogIkFRQUIiLCAia3R5IjogIlJTQSIsICJuIjogIm5kN3ZWUTNraW4zS3BKdTd6RUZNTlVPb0ZIQmVDUWRFRTUyOF9iOHo2djNDNnYtQS0zeUdBcTFWTjZmRTluUXdYSmNlZ2ZNdm1MczlCVVllVjZ2M1FzdGhkVFRCdW5FS1l0TVVZUVRmNkpwaHNEb1pHTkt1dnpCY2ZxSlN2TXpCNHdwa3hORm1Pa2M1QVhwRzhnQWJiTTRuS3JDQkdCQ21lZ2RJUEc3U0g3Mk9tejN6YjIwemZfZlo4dHVoUzk1eUJKdndKRjhZRGtCdDViWUV5ZnQ4aVoyWVFGVmRZZW5FMDhKOGRBUGNVQy1HYld6NmJXUm9Xc0xOT21VNkVjSndsSV9tRXRqazA5aTNlVEhOa2Vna3NrZUJOeXhlSkdtaVRtMHRtS1MwOEVvY0VQTDA1UktxSm9XNnhVcHNITDcwSzdzUVRaUDBHSUY1VXBwSkZXMnlVdyJ9", "protected": "eyJ1cmwiOiAiaHR0cDovL2FjbWUtc3J2LmJhci5sb2NhbC9hY21lL25ld2FjY291bnQiLCAiYWxnIjogIkhTMjU2IiwgImtpZCI6ICJiYXIifQ", "signature": "VXYLfPuoClsn_rhPPV8qjspZV1Q7HyX8rXv6odWYnLI"}'
        assert (False, "") == signature_check(logger, message, mkey, json_=True)

    def test_016_sha256_hash_hex_foo(self, logger: logging.Logger) -> None:
        """sha256 digest as hex for foo"""
        assert (
            "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
            == sha256_hash_hex(logger, "foo")
        )

    def test_017_sha256_hash_hex_bar(self, logger: logging.Logger) -> None:
        """sha256 digest as hex for bar"""
        assert (
            "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9"
            == sha256_hash_hex(logger, "bar")
        )

    def test_018_sha256_hash_foo(self, logger: logging.Logger) -> None:
        """sha256 digest for foo"""
        assert b"LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564" == b64_url_encode(
            logger, sha256_hash(logger, "foo")
        )

    def test_019_sha256_hash_bar(self, logger: logging.Logger) -> None:
        """sha256 digest for bar"""
        assert b"_N4rLtula_QIYB-3If6bXDONEO5CnqBPrlURto-_j7k" == b64_url_encode(
            logger, sha256_hash(logger, "bar")
        )

    def test_020_jwk_thumbprint_get_empty(self, logger: logging.Logger) -> None:
        """test jwk_thumbprint_get with empty pubkey"""
        pub_key = None
        assert not jwk_thumbprint_get(logger, pub_key)

    @patch("jwcrypto.jwk.JWK")
    def test_021_jwk_thumbprint_get_with_pubkey(
        self, mock_jwk: MagicMock, logger: logging.Logger
    ) -> None:
        """test jwk_thumbprint_get with pubkey"""
        pub_key = {"pub_key": "pub_key"}
        mock_jwk = Mock()
        assert jwk_thumbprint_get(logger, pub_key)

    @patch("jwcrypto.jwk.JWK")
    def test_022_jwk_thumbprint_get_exception(
        self,
        mock_jwk: MagicMock,
        logger: logging.Logger,
        capture_logs: Callable[..., AbstractContextManager[Any]],
    ) -> None:
        """test jwk_thumbprint_get with exception from JWK"""
        pub_key = {"pub_key": "pub_key"}
        mock_jwk.side_effect = Exception("exc_jwk_jwk")
        with capture_logs("test_a2c", level="INFO") as lcm:
            assert not jwk_thumbprint_get(logger, pub_key)
        assert (
            "ERROR:test_a2c:Could not get the JWKEY thumbprint from public key: exc_jwk_jwk"
            in lcm.output
        )

    def test_023_string_sanitize_plain(self, logger: logging.Logger) -> None:
        """test string_sanitize() plain string"""
        unsafe_string = "foo"
        assert "foo" == string_sanitize(logger, unsafe_string)

    def test_024_string_sanitize_newline(self, logger: logging.Logger) -> None:
        """test string_sanitize() with newline"""
        unsafe_string = "foo\n;"
        assert "foo;" == string_sanitize(logger, unsafe_string)

    def test_025_string_sanitize_non_ascii(self, logger: logging.Logger) -> None:
        """test string_sanitize() drops non-ascii"""
        unsafe_string = "fooö"
        assert "foo" == string_sanitize(logger, unsafe_string)

    def test_026_string_sanitize_non_ascii_repeat(
        self, logger: logging.Logger
    ) -> None:
        """test string_sanitize() drops non-ascii (repeat case)"""
        unsafe_string = "fooö"
        assert "foo" == string_sanitize(logger, unsafe_string)

    def test_027_string_sanitize_spaces(self, logger: logging.Logger) -> None:
        """test string_sanitize() collapses trailing spaces"""
        unsafe_string = "foo    "
        assert "foo " == string_sanitize(logger, unsafe_string)

    def test_028_string_sanitize_tab(self, logger: logging.Logger) -> None:
        """test string_sanitize() converts tab to spaces then collapses"""
        unsafe_string = "foo\t"
        assert "foo " == string_sanitize(logger, unsafe_string)

    def test_029_generate_random_string_charset_and_secrets(
        self, logger: logging.Logger
    ) -> None:
        """generate_random_string uses secrets and alphanumeric charset"""
        from string import ascii_letters, digits

        with patch(
            "acme2certifier.acme_srv.helpers.crypto.secrets.choice",
            side_effect=lambda seq: seq[0],
        ) as mock_choice:
            result = generate_random_string(logger, 8)
        assert 8 == mock_choice.call_count
        assert result == "0" * 8
        for char in generate_random_string(logger, 64):
            assert char in digits + ascii_letters

    def test_030_unsupported_jwk_detail_ignores_rsa(
        self, logger: logging.Logger
    ) -> None:
        """RSA JWKs are never rejected by the AKP support gate"""
        assert unsupported_jwk_detail(logger, {"kty": "RSA", "alg": "RS256"}) is None

    def test_031_unsupported_jwk_detail_akp_when_unsupported(
        self, logger: logging.Logger
    ) -> None:
        """AKP JWKs get a clear detail when jwcrypto has no AKP support"""
        with patch(
            "acme2certifier.acme_srv.helpers.crypto.akp_jwk_supported",
            return_value=False,
        ):
            detail = unsupported_jwk_detail(
                logger, {"kty": "AKP", "alg": "ML-DSA-44", "pub": "x"}
            )
        assert (
            detail
            == 'JWK key type "AKP" (alg "ML-DSA-44") is not supported by this ACME server'
        )

    def test_032_unsupported_jwk_detail_akp_when_supported(
        self, logger: logging.Logger
    ) -> None:
        """AKP JWKs are allowed when jwcrypto registers AKP"""
        with patch(
            "acme2certifier.acme_srv.helpers.crypto.akp_jwk_supported",
            return_value=True,
        ):
            assert (
                unsupported_jwk_detail(
                    logger, {"kty": "AKP", "alg": "ML-DSA-65", "pub": "x"}
                )
                is None
            )

    def test_033_signature_check_rejects_akp_before_jwcrypto(
        self, logger: logging.Logger
    ) -> None:
        """signature_check returns the AKP detail without calling jwcrypto load"""
        pub_key = {"kty": "AKP", "alg": "ML-DSA-87", "pub": "x"}
        with (
            patch(
                "acme2certifier.acme_srv.helpers.crypto.akp_jwk_supported",
                return_value=False,
            ),
            patch("acme2certifier.acme_srv.helpers.crypto.jwk.JWK") as mock_jwk,
        ):
            ok, err = signature_check(logger, '{"protected":"e30"}', pub_key)
        assert ok is False
        assert err == (
            'JWK key type "AKP" (alg "ML-DSA-87") is not supported by this ACME server'
        )
        mock_jwk.assert_not_called()

    def test_034_akp_jwk_supported_reads_registry(
        self, logger: logging.Logger
    ) -> None:
        """akp_jwk_supported mirrors jwcrypto JWKTypesRegistry membership"""
        import acme2certifier.acme_srv.helpers.crypto as crypto_mod

        crypto_mod._AKP_SUPPORTED = None
        with patch.object(
            crypto_mod.jwk,
            "JWKTypesRegistry",
            {"EC": object(), "RSA": object()},
        ):
            assert akp_jwk_supported(logger) is False
        crypto_mod._AKP_SUPPORTED = None
        with patch.object(
            crypto_mod.jwk,
            "JWKTypesRegistry",
            {"AKP": object()},
        ):
            assert akp_jwk_supported(logger) is True
        crypto_mod._AKP_SUPPORTED = None
