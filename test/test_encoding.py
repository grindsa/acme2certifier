# -*- coding: utf-8 -*-
"""Tests for acme_srv.helpers.encoding."""

from __future__ import annotations

import logging

import pytest

from acme2certifier.acme_srv.helpers.encoding import (
    b64_decode,
    b64_encode,
    b64_url_decode,
    b64_url_encode,
    b64_url_recode,
    b64decode_pad,
    build_pem_file,
    convert_byte_to_string,
    convert_string_to_byte,
)

pytestmark = pytest.mark.usefixtures("clear_config_cache", "_silence_logging")


def test_001_helper_b64decode_pad(logger: logging.Logger) -> None:
    """test b64decode_pad() method with a regular base64 encoded string"""
    assert "this-is-foo-correctly-padded" == b64decode_pad(
        logger, "dGhpcy1pcy1mb28tY29ycmVjdGx5LXBhZGRlZA=="
    )


def test_002_helper_b64decode_pad(logger: logging.Logger) -> None:
    """test b64decode_pad() method with a regular base64 encoded string"""
    assert "this-is-foo-with-incorrect-padding" == b64decode_pad(
        logger, "dGhpcy1pcy1mb28td2l0aC1pbmNvcnJlY3QtcGFkZGluZw"
    )


def test_003_helper_b64decode_pad(logger: logging.Logger) -> None:
    """test b64 decoding failure"""
    assert "ERR: b64 decoding error" == b64decode_pad(logger, "b")


def test_033_helper_b64_url_recode(logger: logging.Logger) -> None:
    """test base64url recode to base64 - add padding for 1 char"""
    assert "fafafaf=" == b64_url_recode(logger, "fafafaf")


def test_034_helper_b64_url_recode(logger: logging.Logger) -> None:
    """test base64url recode to base64 - add padding for 2 char"""
    assert "fafafa==" == b64_url_recode(logger, "fafafa")


def test_035_helper_b64_url_recode(logger: logging.Logger) -> None:
    """test base64url recode to base64 - add padding for 3 char"""
    assert "fafaf===" == b64_url_recode(logger, "fafaf")


def test_036_helper_b64_url_recode(logger: logging.Logger) -> None:
    """test base64url recode to base64 - no padding"""
    assert "fafafafa" == b64_url_recode(logger, "fafafafa")


def test_037_helper_b64_url_recode(logger: logging.Logger) -> None:
    """test base64url replace - with + and pad"""
    assert "fafa+f==" == b64_url_recode(logger, "fafa-f")


def test_038_helper_b64_url_recode(logger: logging.Logger) -> None:
    """test base64url replace _ with / and pad"""
    assert "fafa/f==" == b64_url_recode(logger, "fafa_f")


def test_039_helper_b64_url_recode(logger: logging.Logger) -> None:
    """test base64url recode to base64 - add padding for 1 char"""
    assert "fafafaf=" == b64_url_recode(logger, b"fafafaf")


def test_040_helper_b64_url_recode(logger: logging.Logger) -> None:
    """test base64url recode to base64 - add padding for 2 char"""
    assert "fafafa==" == b64_url_recode(logger, b"fafafa")


def test_041_helper_b64_url_recode(logger: logging.Logger) -> None:
    """test base64url recode to base64 - add padding for 3 char"""
    assert "fafaf===" == b64_url_recode(logger, b"fafaf")


def test_042_helper_b64_url_recode(logger: logging.Logger) -> None:
    """test base64url recode to base64 - no padding"""
    assert "fafafafa" == b64_url_recode(logger, b"fafafafa")


def test_043_helper_b64_url_recode(logger: logging.Logger) -> None:
    """test base64url replace - with + and pad"""
    assert "fafa+f==" == b64_url_recode(logger, b"fafa-f")


def test_044_helper_b64_url_recode(logger: logging.Logger) -> None:
    """test base64url replace _ with / and pad"""
    assert "fafa/f==" == b64_url_recode(logger, b"fafa_f")


def test_045_helper_b64_url_recode(logger: logging.Logger) -> None:
    """test base64url replace _ with / and pad"""
    assert "fafa/f==" == b64_url_recode(logger, b"fafa_f")


def test_063_helper_build_pem_file(logger: logging.Logger) -> None:
    """test build_pem_file without exsting content"""
    existing = None
    cert = "cert"
    assert (
        "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n"
        == build_pem_file(logger, existing, cert, True)
    )


def test_064_helper_build_pem_file(logger: logging.Logger) -> None:
    """test build_pem_file with exsting content"""
    existing = "existing"
    cert = "cert"
    assert (
        "existing-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n"
        == build_pem_file(logger, existing, cert, True)
    )


def test_065_helper_build_pem_file(logger: logging.Logger) -> None:
    """test build_pem_file with long cert (to test wrap)"""
    existing = None
    cert = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert (
        "-----BEGIN CERTIFICATE-----\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\naaaaaaaaa\n-----END CERTIFICATE-----\n"
        == build_pem_file(logger, existing, cert, True)
    )


def test_066_helper_build_pem_file(logger: logging.Logger) -> None:
    """test build_pem_file with long cert (to test wrap)"""
    existing = None
    cert = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert (
        "-----BEGIN CERTIFICATE-----\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n-----END CERTIFICATE-----\n"
        == build_pem_file(logger, existing, cert, False)
    )


def test_067_helper_build_pem_file(logger: logging.Logger) -> None:
    """test build_pem_file with long cert (to test wrap)"""
    existing = "existing"
    cert = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert (
        "existing-----BEGIN CERTIFICATE-----\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n-----END CERTIFICATE-----\n"
        == build_pem_file(logger, existing, cert, False)
    )


def test_068_helper_build_pem_file(logger: logging.Logger) -> None:
    """test build_pem_file for CSR"""
    existing = None
    csr = "MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBvH7P73CwR7AF/WGeTfIDLlMWD6VZV3CTZBF0AwNMTFU/zbdAX8r63pzElX/5C5ZVsc36XHqdAJcioJlI33uE3RhOSvDyOcDgWlnPK9gj2soQ7enizGqd1u7hf6C3IwFtc4uGNOU3Z/tnTzVdYiCSKS+5lTZfMxn4FtEUN+w90NHBvC+AlTo3Gl0gqbYOZgg/UwWj60u7S2gBzSeb2/w62Z7bz+SknGZbeI4ySo30ET6oCSCAUN42jE+1dHI/Y+tGBtqP3h7W7OezKeLsJjD9r07U0+uMoVCY9oKTyT0gK8+gsde0tpt6QKa93HJGUPAP9ehrKCl335QcJESFw67/AgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEAf4cdGpYHLqX+06BFF7+NqXLmKvc7n66vAfevLN75eu/pCXhhRSdpXvcYm+mAVEXJCPaG2kFGt6wfBvVWoVX/91d+OuAtiUHmhY95Oi7g3RF3ThCrvT2mR4zsNiKgC34jXbl9489iIiFRBQXkq2fLwN5JwBYutUENwkDIeApRRbmUzTDbar1xoBAQ3GjVtOAEjHc/3S1yyKkCpM6Qkg8uWOJAXw9INJqH6x55nMZrvTUuXkURc/mvhV+bp2vdKoigGvfa3VVfoAI0BZLQMohQ9QLKoNQsKxEs3JidvpZrl3o23LMGEPoJs3zIuowTa217PHwdBw4UwtD7KxJK/+344A=="
    result = "-----BEGIN CERTIFICATE REQUEST-----\nMIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBvH7P73CwR7AF/WGeTfIDLlMWD6VZV3CT\nZBF0AwNMTFU/zbdAX8r63pzElX/5C5ZVsc36XHqdAJcioJlI33uE3RhOSvDyOcDg\nWlnPK9gj2soQ7enizGqd1u7hf6C3IwFtc4uGNOU3Z/tnTzVdYiCSKS+5lTZfMxn4\nFtEUN+w90NHBvC+AlTo3Gl0gqbYOZgg/UwWj60u7S2gBzSeb2/w62Z7bz+SknGZb\neI4ySo30ET6oCSCAUN42jE+1dHI/Y+tGBtqP3h7W7OezKeLsJjD9r07U0+uMoVCY\n9oKTyT0gK8+gsde0tpt6QKa93HJGUPAP9ehrKCl335QcJESFw67/AgMBAAGgOTA3\nBgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJh\nci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEAf4cdGpYHLqX+06BFF7+NqXLmKvc7\nn66vAfevLN75eu/pCXhhRSdpXvcYm+mAVEXJCPaG2kFGt6wfBvVWoVX/91d+OuAt\niUHmhY95Oi7g3RF3ThCrvT2mR4zsNiKgC34jXbl9489iIiFRBQXkq2fLwN5JwBYu\ntUENwkDIeApRRbmUzTDbar1xoBAQ3GjVtOAEjHc/3S1yyKkCpM6Qkg8uWOJAXw9I\nNJqH6x55nMZrvTUuXkURc/mvhV+bp2vdKoigGvfa3VVfoAI0BZLQMohQ9QLKoNQs\nKxEs3JidvpZrl3o23LMGEPoJs3zIuowTa217PHwdBw4UwtD7KxJK/+344A==\n-----END CERTIFICATE REQUEST-----\n"
    assert result == build_pem_file(logger, existing, csr, False, True)


def test_069_helper_b64_decode(logger: logging.Logger) -> None:
    """test bas64 decoder for string value"""
    assert "test" == b64_decode(logger, "dGVzdA==")


def test_070_helper_b64_decode(logger: logging.Logger) -> None:
    """test bas64 decoder for byte value"""
    assert "test" == b64_decode(logger, b"dGVzdA==")


def test_087_helper_convert_byte_to_string() -> None:
    """convert byte2string for a string value"""
    assert "foo" == convert_byte_to_string("foo")


def test_088_helper_convert_byte_to_string() -> None:
    """convert byte2string for a string value"""
    assert "foo" == convert_byte_to_string("foo")


def test_089_helper_convert_byte_to_string() -> None:
    """convert byte2string for a string value"""
    assert "foo" != convert_byte_to_string("foobar")


def test_090_helper_convert_byte_to_string() -> None:
    """convert byte2string for a string value"""
    assert "foo" != convert_byte_to_string(b"foobar")


def test_091_helper_b64_url_encode(logger: logging.Logger) -> None:
    """test b64_url_encode of string"""
    assert b"c3RyaW5n" == b64_url_encode(logger, "string")


def test_092_helper_b64_url_encode(logger: logging.Logger) -> None:
    """test b64_url_encode of byte"""
    assert b"Ynl0ZQ" == b64_url_encode(logger, b"byte")


def test_095_helper_convert_string_to_byte() -> None:
    """convert string value to byte"""
    value = "foo.bar"
    assert b"foo.bar" == convert_string_to_byte(value)


def test_096_helper_convert_string_to_byte() -> None:
    """convert string value to byte"""
    value = b"foo.bar"
    assert b"foo.bar" == convert_string_to_byte(value)


def test_097_helper_convert_string_to_byte() -> None:
    """convert string value to byte"""
    value = b""
    assert b"" == convert_string_to_byte(value)


def test_098_helper_convert_string_to_byte() -> None:
    """convert string value to byte"""
    value = ""
    assert b"" == convert_string_to_byte(value)


def test_099_helper_convert_string_to_byte() -> None:
    """convert string value to byte"""
    value = None
    assert not convert_string_to_byte(value)


def test_208_b64_encode(logger: logging.Logger) -> None:
    """base64 encode string"""
    assert "Zm9v" == b64_encode(logger, b"foo")


def test_209_b64_encode(logger: logging.Logger) -> None:
    """base64 encode string"""
    assert "YmFyMQ==" == b64_encode(logger, b"bar1")


def test_210_b64_encode(logger: logging.Logger) -> None:
    """base64 encode string"""
    assert "YmFyMTI=" == b64_encode(logger, b"bar12")


def test_519_b64_url_decode(logger: logging.Logger) -> None:
    """test b64_url_decode()"""
    assert "foo" == b64_url_decode(logger, "Zm9v")


def test_520_b64_url_decode(logger: logging.Logger) -> None:
    """test b64_url_decode()"""
    assert "thisisateststring" == b64_url_decode(logger, "dGhpc2lzYXRlc3RzdHJpbmc")


def test_521_b64_url_decode(logger: logging.Logger) -> None:
    """test b64_url_decode()"""
    assert "thisisateststring" == b64_url_decode(logger, "dGhpc2lzYXRlc3RzdHJpbmc=")


def test_522_b64_url_decode(logger: logging.Logger) -> None:
    """test b64_url_decode()"""
    assert "thisisateststring" == b64_url_decode(logger, "dGhpc2lzYXRlc3RzdHJpbmc    ")
