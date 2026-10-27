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
    decode_deserialize,
    decode_message,
    generate_random_string,
    jwk_thumbprint_get,
    sha256_hash,
    sha256_hash_hex,
    signature_check,
    string_sanitize,
)
from acme2certifier.acme_srv.helpers.encoding import b64_url_encode

pytestmark = pytest.mark.usefixtures("clear_config_cache", "_silence_logging")


def test_004_helper_decode_deserialize(logger: logging.Logger) -> None:
    """test successful deserialization of a b64 encoded string"""
    assert {"a": "b", "c": "d"} == decode_deserialize(
        logger, "eyJhIiA6ICJiIiwgImMiIDogImQifQ=="
    )


def test_005_helper_decode_deserialize(logger: logging.Logger) -> None:
    """test failed deserialization of a b64 encoded string"""
    assert "ERR: Json decoding error" == decode_deserialize(
        logger, "Zm9vLXdoaWNoLWNhbm5vdC1iZS1qc29uaXplZA=="
    )


def test_017_helper_signature_check(logger: logging.Logger) -> None:
    """successful validation of singature"""
    mkey = {
        "alg": "RS256",
        "e": "AQAB",
        "kty": "RSA",
        "n": "2CFMV4MK6Uo_2GQWa0KVWlzffgSDiLwur4ujSZkCRzbA3w5p1ABJgr7l_P84HpRv8R8rGL67hqmDJuT52mGD6fMVAhHPX5pSdtyZlQQuzpXonzNmHbG1DbMSiXrxg5jWVXchCxHx82wAt9Kf13O5ATxD0WOBB5FffpqQHh8zTf29jTL4vBd8N57ce17ZgNWl_EcoByjigqNFJcO0rrvrf6xyNaO9nbun4PAMJTLbfVa6CiEqjnjYMX80VYLH4fCqsAZgxIoli_D2j9P5Kq6KZZUL_bZ2QQV4UuwWZvh6tcA393YQLeMARnhWI6dqlZVdcU74NXi9NhSxcMkM8nZZ8Q",
    }
    message = '{"protected": "eyJub25jZSI6ICI3N2M3MmViMDE5NDc0YzBjOWIzODk5MmU4ZjRkMDIzYSIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIn0","payload": "eyJzdGF0dXMiOiJkZWFjdGl2YXRlZCJ9","signature": "QYbMYZ1Dk8dHKqOwWBQHvWdnGD7donGZObb2Ry_Y5PsHpcTrj8Y2CM57SNVAR9V0ePg4vhK3-IbwYAKbhZV8jF7E-ylZaYm4PSQcumKLI55qvDiEvDiZ0gmjf_GAcsC40TwBa11lzR1u0dQYxOlQ_y9ak6705c5bM_V4_ttQeslJXCfVIQoV-sZS0Z6tJfy5dPVDR7JYG77bZbD3K-HCCaVbT7ilqcf00rA16lvw13zZnIgbcZsbW-eJ2BM_QxE24PGqc_vMfAxIiUG0VY7DqrKumLs91lHHTEie8I-CapH6AetsBhGtRcB6EL_Rn6qGQZK9YBpvoXANv_qF2-zQkQ"}'
    assert (True, None) == signature_check(logger, message, mkey)


def test_018_helper_signature_check(logger: logging.Logger) -> None:
    """failed validatio of singature  wrong key"""
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


def test_019_helper_signature_check(logger: logging.Logger) -> None:
    """failed validatio of singature  faulty key"""
    mkey = {
        "alg": "rs256",
        "e": "AQAB",
        "n": "zncgRHCp22-29g9FO4Hn02iyS1Fo4Y1tB-6cucH1yKSxM6bowjAaVa4HkAnIxgF6Zj9qLROgQR84YjMPeNkq8woBRz1aziDiTIOc0D2aXvLgZbuFGesvxoSGd6uyxjyyV7ONwZEpB8QtDW0I3shlhosKB3Ni1NFu55bPUP9RvxUdPzRRuhxUMHc1CXre1KR0eQmQdNZT6tgQVxpv2lb-iburBADjivBRyrI3k3NmXkYknBggAu8JInaFY4T8pVK0jTwP-f3-0eAV1bg99Rm7uXNXl7SKpQ3oGihwy2OK-XAc59v6C3n4Wq9QpzGkFWsOOlp4zEf13L3_UKugeExEqw",
    }
    message = '{"protected": "eyJub25jZSI6ICI3N2M3MmViMDE5NDc0YzBjOWIzODk5MmU4ZjRkMDIzYSIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIn0","payload": "eyJzdGF0dXMiOiJkZWFjdGl2YXRlZCJ9","signature": "QYbMYZ1Dk8dHKqOwWBQHvWdnGD7donGZObb2Ry_Y5PsHpcTrj8Y2CM57SNVAR9V0ePg4vhK3-IbwYAKbhZV8jF7E-ylZaYm4PSQcumKLI55qvDiEvDiZ0gmjf_GAcsC40TwBa11lzR1u0dQYxOlQ_y9ak6705c5bM_V4_ttQeslJXCfVIQoV-sZS0Z6tJfy5dPVDR7JYG77bZbD3K-HCCaVbT7ilqcf00rA16lvw13zZnIgbcZsbW-eJ2BM_QxE24PGqc_vMfAxIiUG0VY7DqrKumLs91lHHTEie8I-CapH6AetsBhGtRcB6EL_Rn6qGQZK9YBpvoXANv_qF2-zQkQ"}'
    ok, detail = signature_check(logger, message, mkey)
    assert not ok
    assert detail.startswith('Unknown type "None", valid types are:'), detail


def test_020_helper_signature_check(logger: logging.Logger) -> None:
    """failed validatio of singature  no key"""
    mkey = {}
    message = '{"protected": "eyJub25jZSI6ICI3N2M3MmViMDE5NDc0YzBjOWIzODk5MmU4ZjRkMDIzYSIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIn0","payload": "eyJzdGF0dXMiOiJkZWFjdGl2YXRlZCJ9","signature": "QYbMYZ1Dk8dHKqOwWBQHvWdnGD7donGZObb2Ry_Y5PsHpcTrj8Y2CM57SNVAR9V0ePg4vhK3-IbwYAKbhZV8jF7E-ylZaYm4PSQcumKLI55qvDiEvDiZ0gmjf_GAcsC40TwBa11lzR1u0dQYxOlQ_y9ak6705c5bM_V4_ttQeslJXCfVIQoV-sZS0Z6tJfy5dPVDR7JYG77bZbD3K-HCCaVbT7ilqcf00rA16lvw13zZnIgbcZsbW-eJ2BM_QxE24PGqc_vMfAxIiUG0VY7DqrKumLs91lHHTEie8I-CapH6AetsBhGtRcB6EL_Rn6qGQZK9YBpvoXANv_qF2-zQkQ"}'
    assert (False, "No key specified.") == signature_check(logger, message, mkey)


def test_031_helper_generate_random_string(logger: logging.Logger) -> None:
    """test date_to_uts_utc without format"""
    assert 5 == len(generate_random_string(logger, 5))


def test_032_helper_generate_random_string(logger: logging.Logger) -> None:
    """test date_to_uts_utc without format"""
    assert 15 == len(generate_random_string(logger, 15))


def test_046_helper_decode_message(logger: logging.Logger) -> None:
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


def test_047_helper_decode_message(logger: logging.Logger) -> None:
    """decode message with empty payload - certbot issue"""
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
def test_048_helper_decode_message(
    mock_json: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """decode message with with exception during decoding"""
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


def test_191_helper_signature_check(logger: logging.Logger) -> None:
    """sucessful validation symmetric key"""
    mkey = '{"k": "ZndUSkZvVldvMEFiRzQ5VWNCdERtNkNBNnBTcTl4czNKVEVxdUZiaEdpZXZNUVJBVmRuSFREcDJYX2s3X0NxTA", "kty": "oct"}'
    message = '{"payload": "eyJlIjogIkFRQUIiLCAia3R5IjogIlJTQSIsICJuIjogIm5kN3ZWUTNraW4zS3BKdTd6RUZNTlVPb0ZIQmVDUWRFRTUyOF9iOHo2djNDNnYtQS0zeUdBcTFWTjZmRTluUXdYSmNlZ2ZNdm1MczlCVVllVjZ2M1FzdGhkVFRCdW5FS1l0TVVZUVRmNkpwaHNEb1pHTkt1dnpCY2ZxSlN2TXpCNHdwa3hORm1Pa2M1QVhwRzhnQWJiTTRuS3JDQkdCQ21lZ2RJUEc3U0g3Mk9tejN6YjIwemZfZlo4dHVoUzk1eUJKdndKRjhZRGtCdDViWUV5ZnQ4aVoyWVFGVmRZZW5FMDhKOGRBUGNVQy1HYld6NmJXUm9Xc0xOT21VNkVjSndsSV9tRXRqazA5aTNlVEhOa2Vna3NrZUJOeXhlSkdtaVRtMHRtS1MwOEVvY0VQTDA1UktxSm9XNnhVcHNITDcwSzdzUVRaUDBHSUY1VXBwSkZXMnlVdyJ9", "protected": "eyJ1cmwiOiAiaHR0cDovL2FjbWUtc3J2LmJhci5sb2NhbC9hY21lL25ld2FjY291bnQiLCAiYWxnIjogIkhTMjU2IiwgImtpZCI6ICJiYXIifQ", "signature": "VXYLfPuoClsn_rhPPV8qjspZV1Q7HyX8rXv6odWYnLI"}'
    assert (True, None) == signature_check(logger, message, mkey, json_=True)


def test_192_helper_signature_check(logger: logging.Logger) -> None:
    """sucessful validation wrong symmetric key"""
    mkey = '{"k": "ZndUSkZvVldvMEFiRzQ5VWNCdERtNkNBNnBTcTl4czNKVEVxdUZiaEdpZXZNUVJBVmRuSFREcDJYX2s3X0NxvA", "kty": "oct"}'
    message = '{"payload": "eyJlIjogIkFRQUIiLCAia3R5IjogIlJTQSIsICJuIjogIm5kN3ZWUTNraW4zS3BKdTd6RUZNTlVPb0ZIQmVDUWRFRTUyOF9iOHo2djNDNnYtQS0zeUdBcTFWTjZmRTluUXdYSmNlZ2ZNdm1MczlCVVllVjZ2M1FzdGhkVFRCdW5FS1l0TVVZUVRmNkpwaHNEb1pHTkt1dnpCY2ZxSlN2TXpCNHdwa3hORm1Pa2M1QVhwRzhnQWJiTTRuS3JDQkdCQ21lZ2RJUEc3U0g3Mk9tejN6YjIwemZfZlo4dHVoUzk1eUJKdndKRjhZRGtCdDViWUV5ZnQ4aVoyWVFGVmRZZW5FMDhKOGRBUGNVQy1HYld6NmJXUm9Xc0xOT21VNkVjSndsSV9tRXRqazA5aTNlVEhOa2Vna3NrZUJOeXhlSkdtaVRtMHRtS1MwOEVvY0VQTDA1UktxSm9XNnhVcHNITDcwSzdzUVRaUDBHSUY1VXBwSkZXMnlVdyJ9", "protected": "eyJ1cmwiOiAiaHR0cDovL2FjbWUtc3J2LmJhci5sb2NhbC9hY21lL25ld2FjY291bnQiLCAiYWxnIjogIkhTMjU2IiwgImtpZCI6ICJiYXIifQ", "signature": "VXYLfPuoClsn_rhPPV8qjspZV1Q7HyX8rXv6odWYnLI"}'
    if int("%i%i" % (sys.version_info[0], sys.version_info[1])) <= 36:
        error = "Verification failed for all signatures[\"Failed: [InvalidJWSSignature('Verification failed',)]\"]"
    else:
        error = "Verification failed for all signatures[\"Failed: [InvalidJWSSignature('Verification failed')]\"]"
    assert (False, error) == signature_check(logger, message, mkey, json_=True)


def test_193_helper_signature_check(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """sucessful validation wrong symmetric key without json_ flag set"""
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


def test_194_helper_signature_check(logger: logging.Logger) -> None:
    """sucessful validation invalid key"""
    mkey = "invalid key"
    message = '{"payload": "eyJlIjogIkFRQUIiLCAia3R5IjogIlJTQSIsICJuIjogIm5kN3ZWUTNraW4zS3BKdTd6RUZNTlVPb0ZIQmVDUWRFRTUyOF9iOHo2djNDNnYtQS0zeUdBcTFWTjZmRTluUXdYSmNlZ2ZNdm1MczlCVVllVjZ2M1FzdGhkVFRCdW5FS1l0TVVZUVRmNkpwaHNEb1pHTkt1dnpCY2ZxSlN2TXpCNHdwa3hORm1Pa2M1QVhwRzhnQWJiTTRuS3JDQkdCQ21lZ2RJUEc3U0g3Mk9tejN6YjIwemZfZlo4dHVoUzk1eUJKdndKRjhZRGtCdDViWUV5ZnQ4aVoyWVFGVmRZZW5FMDhKOGRBUGNVQy1HYld6NmJXUm9Xc0xOT21VNkVjSndsSV9tRXRqazA5aTNlVEhOa2Vna3NrZUJOeXhlSkdtaVRtMHRtS1MwOEVvY0VQTDA1UktxSm9XNnhVcHNITDcwSzdzUVRaUDBHSUY1VXBwSkZXMnlVdyJ9", "protected": "eyJ1cmwiOiAiaHR0cDovL2FjbWUtc3J2LmJhci5sb2NhbC9hY21lL25ld2FjY291bnQiLCAiYWxnIjogIkhTMjU2IiwgImtpZCI6ICJiYXIifQ", "signature": "VXYLfPuoClsn_rhPPV8qjspZV1Q7HyX8rXv6odWYnLI"}'
    assert (False, "") == signature_check(logger, message, mkey, json_=True)


def test_204_sha256_hash_hex(logger: logging.Logger) -> None:
    """sha256 digest as hex file"""
    assert (
        "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
        == sha256_hash_hex(logger, "foo")
    )


def test_205_sha256_hash_hex(logger: logging.Logger) -> None:
    """sha256 digest as hex file"""
    assert (
        "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9"
        == sha256_hash_hex(logger, "bar")
    )


def test_206_sha256_hash(logger: logging.Logger) -> None:
    """sha256 digest"""
    assert b"LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564" == b64_url_encode(
        logger, sha256_hash(logger, "foo")
    )


def test_207_sha256_hash(logger: logging.Logger) -> None:
    """sha256 digest"""
    assert b"_N4rLtula_QIYB-3If6bXDONEO5CnqBPrlURto-_j7k" == b64_url_encode(
        logger, sha256_hash(logger, "bar")
    )


def test_250_jwk_thumbprint_get(logger: logging.Logger) -> None:
    """test jwk_thumbprint_get with empty pubkey"""
    pub_key = None
    assert not jwk_thumbprint_get(logger, pub_key)


@patch("jwcrypto.jwk.JWK")
def test_251_jwk_thumbprint_get(mock_jwk: MagicMock, logger: logging.Logger) -> None:
    """test jwk_thumbprint_get with  pubkey"""
    pub_key = {"pub_key": "pub_key"}
    mock_jwk = Mock()
    assert jwk_thumbprint_get(logger, pub_key)


@patch("jwcrypto.jwk.JWK")
def test_252_jwk_thumbprint_get(
    mock_jwk: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """test jwk_thumbprint_get with  pubkey"""
    pub_key = {"pub_key": "pub_key"}
    mock_jwk.side_effect = Exception("exc_jwk_jwk")
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not jwk_thumbprint_get(logger, pub_key)
    assert (
        "ERROR:test_a2c:Could not get the JWKEY thumbprint from public key: exc_jwk_jwk"
        in lcm.output
    )


def test_337_logger_challenges_modify(logger: logging.Logger) -> None:
    """test string_sanitize()"""
    unsafe_string = "foo"
    assert "foo" == string_sanitize(logger, unsafe_string)


def test_338_logger_challenges_modify(logger: logging.Logger) -> None:
    """test string_sanitize()"""
    unsafe_string = "foo\n;"
    assert "foo;" == string_sanitize(logger, unsafe_string)


def test_339_logger_challenges_modify(logger: logging.Logger) -> None:
    """test string_sanitize()"""
    unsafe_string = "fooö"
    assert "foo" == string_sanitize(logger, unsafe_string)


def test_340_logger_challenges_modify(logger: logging.Logger) -> None:
    """test string_sanitize()"""
    unsafe_string = "fooö"
    assert "foo" == string_sanitize(logger, unsafe_string)


def test_341_logger_challenges_modify(logger: logging.Logger) -> None:
    """test string_sanitize()"""
    unsafe_string = "foo    "
    assert "foo " == string_sanitize(logger, unsafe_string)


def test_342_logger_challenges_modify(logger: logging.Logger) -> None:
    """test string_sanitize()"""
    unsafe_string = "foo\t"
    assert "foo " == string_sanitize(logger, unsafe_string)


def test_628_generate_random_string_charset_and_secrets(logger: logging.Logger) -> None:
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
