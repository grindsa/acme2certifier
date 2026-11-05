# -*- coding: utf-8 -*-
"""Tests for acme_srv.helpers.encoding."""

from __future__ import annotations

import base64
import logging

import pytest

from acme2certifier.acme_srv.helpers.encoding import (
    B64_DECODE_ERROR,
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


class TestEncoding:
    """Central tests for encoding helpers."""

    def test_001_b64decode_pad(self, logger: logging.Logger) -> None:
        """test b64decode_pad() method with a regular base64 encoded string"""
        assert "this-is-foo-correctly-padded" == b64decode_pad(
            logger, "dGhpcy1pcy1mb28tY29ycmVjdGx5LXBhZGRlZA=="
        )

    def test_002_b64decode_pad(self, logger: logging.Logger) -> None:
        """test b64decode_pad() method with a regular base64 encoded string"""
        assert "this-is-foo-with-incorrect-padding" == b64decode_pad(
            logger, "dGhpcy1pcy1mb28td2l0aC1pbmNvcnJlY3QtcGFkZGluZw"
        )

    def test_003_b64decode_pad(self, logger: logging.Logger) -> None:
        """test b64 decoding failure"""
        assert B64_DECODE_ERROR == b64decode_pad(logger, "b")

    def test_004_b64decode_pad(self, logger: logging.Logger) -> None:
        """valid base64 of non-UTF-8 bytes returns the error marker"""
        payload = base64.urlsafe_b64encode(b"\xff\xfe").decode()
        assert B64_DECODE_ERROR == b64decode_pad(logger, payload)

    def test_005_b64decode_pad(self, logger: logging.Logger) -> None:
        """non-alphabet junk must not decode to an empty string"""
        assert B64_DECODE_ERROR == b64decode_pad(logger, "!!!!")

    def test_006_b64decode_pad(self, logger: logging.Logger) -> None:
        """empty input remains empty (not an error)"""
        assert "" == b64decode_pad(logger, "")

    def test_007_b64decode_pad(self, logger: logging.Logger) -> None:
        """urlsafe alphabet (-/_) round-trips under strict validation"""
        # ">>>" encodes to urlsafe "Pj4-" and exercises altchars under validate=True.
        encoded = base64.urlsafe_b64encode(b">>>").decode().rstrip("=")
        assert "-" in encoded
        assert ">>>" == b64decode_pad(logger, encoded)

    def test_008_b64decode_pad(self, logger: logging.Logger) -> None:
        """already-padded input must not gain extra '=' padding"""
        encoded = base64.urlsafe_b64encode(b">>>").decode()
        assert ">>>" == b64decode_pad(logger, encoded)

    def test_009_b64_url_recode(self, logger: logging.Logger) -> None:
        """test base64url recode to base64 - add padding for 1 char"""
        assert "fafafaf=" == b64_url_recode(logger, "fafafaf")

    def test_010_b64_url_recode(self, logger: logging.Logger) -> None:
        """test base64url recode to base64 - add padding for 2 char"""
        assert "fafafa==" == b64_url_recode(logger, "fafafa")

    def test_011_b64_url_recode(self, logger: logging.Logger) -> None:
        """test base64url recode to base64 - add padding for 3 char"""
        assert "fafaf===" == b64_url_recode(logger, "fafaf")

    def test_012_b64_url_recode(self, logger: logging.Logger) -> None:
        """test base64url recode to base64 - no padding"""
        assert "fafafafa" == b64_url_recode(logger, "fafafafa")

    def test_013_b64_url_recode(self, logger: logging.Logger) -> None:
        """test base64url replace - with + and pad"""
        assert "fafa+f==" == b64_url_recode(logger, "fafa-f")

    def test_014_b64_url_recode(self, logger: logging.Logger) -> None:
        """test base64url replace _ with / and pad"""
        assert "fafa/f==" == b64_url_recode(logger, "fafa_f")

    def test_015_b64_url_recode(self, logger: logging.Logger) -> None:
        """test base64url recode to base64 - add padding for 1 char"""
        assert "fafafaf=" == b64_url_recode(logger, b"fafafaf")

    def test_016_b64_url_recode(self, logger: logging.Logger) -> None:
        """test base64url recode to base64 - add padding for 2 char"""
        assert "fafafa==" == b64_url_recode(logger, b"fafafa")

    def test_017_b64_url_recode(self, logger: logging.Logger) -> None:
        """test base64url recode to base64 - add padding for 3 char"""
        assert "fafaf===" == b64_url_recode(logger, b"fafaf")

    def test_018_b64_url_recode(self, logger: logging.Logger) -> None:
        """test base64url recode to base64 - no padding"""
        assert "fafafafa" == b64_url_recode(logger, b"fafafafa")

    def test_019_b64_url_recode(self, logger: logging.Logger) -> None:
        """test base64url replace - with + and pad"""
        assert "fafa+f==" == b64_url_recode(logger, b"fafa-f")

    def test_020_b64_url_recode(self, logger: logging.Logger) -> None:
        """test base64url replace _ with / and pad"""
        assert "fafa/f==" == b64_url_recode(logger, b"fafa_f")

    def test_021_b64_url_recode(self, logger: logging.Logger) -> None:
        """test base64url replace _ with / and pad"""
        assert "fafa/f==" == b64_url_recode(logger, b"fafa_f")

    def test_022_build_pem_file(self, logger: logging.Logger) -> None:
        """test build_pem_file without existing content"""
        existing = None
        cert = "cert"
        assert (
            "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n"
            == build_pem_file(logger, existing, cert, True)
        )

    def test_023_build_pem_file(self, logger: logging.Logger) -> None:
        """test build_pem_file with existing content"""
        existing = "existing"
        cert = "cert"
        assert (
            "existing-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n"
            == build_pem_file(logger, existing, cert, True)
        )

    def test_024_build_pem_file(self, logger: logging.Logger) -> None:
        """test build_pem_file with long cert (to test wrap)"""
        existing = None
        cert = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        assert (
            "-----BEGIN CERTIFICATE-----\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\naaaaaaaaa\n-----END CERTIFICATE-----\n"
            == build_pem_file(logger, existing, cert, True)
        )

    def test_025_build_pem_file(self, logger: logging.Logger) -> None:
        """test build_pem_file with long cert (to test wrap)"""
        existing = None
        cert = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        assert (
            "-----BEGIN CERTIFICATE-----\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n-----END CERTIFICATE-----\n"
            == build_pem_file(logger, existing, cert, False)
        )

    def test_026_build_pem_file(self, logger: logging.Logger) -> None:
        """test build_pem_file with long cert (to test wrap)"""
        existing = "existing"
        cert = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        assert (
            "existing-----BEGIN CERTIFICATE-----\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n-----END CERTIFICATE-----\n"
            == build_pem_file(logger, existing, cert, False)
        )

    def test_027_build_pem_file(self, logger: logging.Logger) -> None:
        """test build_pem_file for CSR"""
        existing = None
        csr = "MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBvH7P73CwR7AF/WGeTfIDLlMWD6VZV3CTZBF0AwNMTFU/zbdAX8r63pzElX/5C5ZVsc36XHqdAJcioJlI33uE3RhOSvDyOcDgWlnPK9gj2soQ7enizGqd1u7hf6C3IwFtc4uGNOU3Z/tnTzVdYiCSKS+5lTZfMxn4FtEUN+w90NHBvC+AlTo3Gl0gqbYOZgg/UwWj60u7S2gBzSeb2/w62Z7bz+SknGZbeI4ySo30ET6oCSCAUN42jE+1dHI/Y+tGBtqP3h7W7OezKeLsJjD9r07U0+uMoVCY9oKTyT0gK8+gsde0tpt6QKa93HJGUPAP9ehrKCl335QcJESFw67/AgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEAf4cdGpYHLqX+06BFF7+NqXLmKvc7n66vAfevLN75eu/pCXhhRSdpXvcYm+mAVEXJCPaG2kFGt6wfBvVWoVX/91d+OuAtiUHmhY95Oi7g3RF3ThCrvT2mR4zsNiKgC34jXbl9489iIiFRBQXkq2fLwN5JwBYutUENwkDIeApRRbmUzTDbar1xoBAQ3GjVtOAEjHc/3S1yyKkCpM6Qkg8uWOJAXw9INJqH6x55nMZrvTUuXkURc/mvhV+bp2vdKoigGvfa3VVfoAI0BZLQMohQ9QLKoNQsKxEs3JidvpZrl3o23LMGEPoJs3zIuowTa217PHwdBw4UwtD7KxJK/+344A=="
        result = "-----BEGIN CERTIFICATE REQUEST-----\nMIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBvH7P73CwR7AF/WGeTfIDLlMWD6VZV3CT\nZBF0AwNMTFU/zbdAX8r63pzElX/5C5ZVsc36XHqdAJcioJlI33uE3RhOSvDyOcDg\nWlnPK9gj2soQ7enizGqd1u7hf6C3IwFtc4uGNOU3Z/tnTzVdYiCSKS+5lTZfMxn4\nFtEUN+w90NHBvC+AlTo3Gl0gqbYOZgg/UwWj60u7S2gBzSeb2/w62Z7bz+SknGZb\neI4ySo30ET6oCSCAUN42jE+1dHI/Y+tGBtqP3h7W7OezKeLsJjD9r07U0+uMoVCY\n9oKTyT0gK8+gsde0tpt6QKa93HJGUPAP9ehrKCl335QcJESFw67/AgMBAAGgOTA3\nBgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJh\nci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEAf4cdGpYHLqX+06BFF7+NqXLmKvc7\nn66vAfevLN75eu/pCXhhRSdpXvcYm+mAVEXJCPaG2kFGt6wfBvVWoVX/91d+OuAt\niUHmhY95Oi7g3RF3ThCrvT2mR4zsNiKgC34jXbl9489iIiFRBQXkq2fLwN5JwBYu\ntUENwkDIeApRRbmUzTDbar1xoBAQ3GjVtOAEjHc/3S1yyKkCpM6Qkg8uWOJAXw9I\nNJqH6x55nMZrvTUuXkURc/mvhV+bp2vdKoigGvfa3VVfoAI0BZLQMohQ9QLKoNQs\nKxEs3JidvpZrl3o23LMGEPoJs3zIuowTa217PHwdBw4UwtD7KxJK/+344A==\n-----END CERTIFICATE REQUEST-----\n"
        assert result == build_pem_file(logger, existing, csr, False, True)

    def test_028_b64_decode(self, logger: logging.Logger) -> None:
        """test bas64 decoder for string value"""
        assert "test" == b64_decode(logger, "dGVzdA==")

    def test_029_b64_decode(self, logger: logging.Logger) -> None:
        """test bas64 decoder for byte value"""
        assert "test" == b64_decode(logger, b"dGVzdA==")

    def test_030_convert_byte_to_string(self) -> None:
        """convert byte2string for a string value"""
        assert "foo" == convert_byte_to_string("foo")

    def test_031_convert_byte_to_string(self) -> None:
        """convert byte2string for a string value"""
        assert "foo" == convert_byte_to_string("foo")

    def test_032_convert_byte_to_string(self) -> None:
        """convert byte2string for a string value"""
        assert "foo" != convert_byte_to_string("foobar")

    def test_033_convert_byte_to_string(self) -> None:
        """convert byte2string for a string value"""
        assert "foo" != convert_byte_to_string(b"foobar")

    def test_034_b64_url_encode(self, logger: logging.Logger) -> None:
        """test b64_url_encode of string"""
        assert b"c3RyaW5n" == b64_url_encode(logger, "string")

    def test_035_b64_url_encode(self, logger: logging.Logger) -> None:
        """test b64_url_encode of byte"""
        assert b"Ynl0ZQ" == b64_url_encode(logger, b"byte")

    def test_036_convert_string_to_byte(self) -> None:
        """convert string value to byte"""
        value = "foo.bar"
        assert b"foo.bar" == convert_string_to_byte(value)

    def test_037_convert_string_to_byte(self) -> None:
        """convert string value to byte"""
        value = b"foo.bar"
        assert b"foo.bar" == convert_string_to_byte(value)

    def test_038_convert_string_to_byte(self) -> None:
        """convert string value to byte"""
        value = b""
        assert b"" == convert_string_to_byte(value)

    def test_039_convert_string_to_byte(self) -> None:
        """convert string value to byte"""
        value = ""
        assert b"" == convert_string_to_byte(value)

    def test_040_convert_string_to_byte(self) -> None:
        """convert string value to byte"""
        value = None
        assert not convert_string_to_byte(value)

    def test_041_b64_encode(self, logger: logging.Logger) -> None:
        """base64 encode string"""
        assert "Zm9v" == b64_encode(logger, b"foo")

    def test_042_b64_encode(self, logger: logging.Logger) -> None:
        """base64 encode string"""
        assert "YmFyMQ==" == b64_encode(logger, b"bar1")

    def test_043_b64_encode(self, logger: logging.Logger) -> None:
        """base64 encode string"""
        assert "YmFyMTI=" == b64_encode(logger, b"bar12")

    def test_044_b64_url_decode(self, logger: logging.Logger) -> None:
        """test b64_url_decode()"""
        assert "foo" == b64_url_decode(logger, "Zm9v")

    def test_045_b64_url_decode(self, logger: logging.Logger) -> None:
        """test b64_url_decode()"""
        assert "thisisateststring" == b64_url_decode(logger, "dGhpc2lzYXRlc3RzdHJpbmc")

    def test_046_b64_url_decode(self, logger: logging.Logger) -> None:
        """test b64_url_decode()"""
        assert "thisisateststring" == b64_url_decode(logger, "dGhpc2lzYXRlc3RzdHJpbmc=")

    def test_047_b64_url_decode(self, logger: logging.Logger) -> None:
        """test b64_url_decode()"""
        assert "thisisateststring" == b64_url_decode(
            logger, "dGhpc2lzYXRlc3RzdHJpbmc    "
        )
