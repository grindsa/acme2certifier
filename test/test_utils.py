# -*- coding: utf-8 -*-
"""Tests for acme_srv.helpers.utils."""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from contextlib import AbstractContextManager
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from acme2certifier.acme_srv.helpers.utils import (
    enrollment_config_log,
    error_dic_get,
    handler_config_check,
    kerberos_kinit_command_resolve,
    radomize_parameter_list,
)

pytestmark = pytest.mark.usefixtures("clear_config_cache", "_silence_logging")


def test_323_error_dic_get(logger: logging.Logger) -> None:
    """test error_dic_get"""
    result = {
        "accountdoesnotexist": "urn:ietf:params:acme:error:accountDoesNotExist",
        "alreadyrevoked": "urn:ietf:params:acme:error:alreadyRevoked",
        "badcsr": "urn:ietf:params:acme:error:badCSR",
        "badpubkey": "urn:ietf:params:acme:error:badPublicKey",
        "badrevocationreason": "urn:ietf:params:acme:error:badRevocationReason",
        "externalaccountrequired": "urn:ietf:params:acme:error:externalAccountRequired",
        "invalidcontact": "urn:ietf:params:acme:error:invalidContact",
        "invalidprofile": "urn:ietf:params:acme:error:invalidProfile",
        "malformed": "urn:ietf:params:acme:error:malformed",
        "ordernotready": "urn:ietf:params:acme:error:orderNotReady",
        "ratelimited": "urn:ietf:params:acme:error:rateLimited",
        "rejectedidentifier": "urn:ietf:params:acme:error:rejectedIdentifier",
        "serverinternal": "urn:ietf:params:acme:error:serverInternal",
        "unauthorized": "urn:ietf:params:acme:error:unauthorized",
        "unsupportedidentifier": "urn:ietf:params:acme:error:unsupportedIdentifier",
        "useractionrequired": "urn:ietf:params:acme:error:userActionRequired",
    }
    assert result == error_dic_get(logger)


def test_469_enrollment_config_log(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """test enrollment_config_log()"""

    class myclass:
        pass

    myclass.foo = "foo_val"
    myclass.bar = "bar_val"
    myclass.password = "password_val"
    myclass.secret = "secret_val"
    myclass.cert_passphrase = "pkcs12_secret"
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not enrollment_config_log(logger, myclass)
    assert (
        "INFO:test_a2c:Enrollment configuration: ['foo: foo_val', 'bar: bar_val']"
        in lcm.output
    )


def test_470_enrollment_config_log_sensitive_name_fragment(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """test enrollment_config_log() skips secret-like attribute name fragments"""

    class myclass:
        pass

    myclass.visible = "ok"
    myclass.client_passphrase_backup = "hidden"
    with capture_logs("test_a2c", level="INFO") as lcm:
        enrollment_config_log(logger, myclass)
    assert "INFO:test_a2c:Enrollment configuration: ['visible: ok']" in lcm.output


def test_471_kerberos_kinit_command_resolve_default(logger: logging.Logger) -> None:
    """bare/default kinit is allowed for PATH lookup"""
    assert "kinit" == kerberos_kinit_command_resolve(logger, None)
    assert "kinit" == kerberos_kinit_command_resolve(logger, "kinit")
    assert "kinit" == kerberos_kinit_command_resolve(logger, "  kinit  ")


def test_472_kerberos_kinit_command_resolve_absolute(logger: logging.Logger) -> None:
    """absolute path with basename kinit is accepted"""
    with TemporaryDirectory() as tmpdir:
        kinit_bin = os.path.join(tmpdir, "kinit")
        with open(kinit_bin, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\n")
        assert os.path.realpath(kinit_bin) == kerberos_kinit_command_resolve(
            logger, kinit_bin
        )


def test_473_kerberos_kinit_command_resolve_debian_alternatives(
    logger: logging.Logger,
) -> None:
    """Debian/Ubuntu kinit -> kinit.mit symlink is accepted"""
    with TemporaryDirectory() as tmpdir:
        kinit_mit = os.path.join(tmpdir, "kinit.mit")
        kinit_link = os.path.join(tmpdir, "kinit")
        with open(kinit_mit, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\n")
        os.symlink(kinit_mit, kinit_link)
        assert os.path.realpath(kinit_mit) == kerberos_kinit_command_resolve(
            logger, kinit_link
        )


def test_474_kerberos_kinit_command_resolve_rejects_relative(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """relative paths are rejected"""
    with capture_logs("test_a2c", level="ERROR") as lcm:
        assert kerberos_kinit_command_resolve(logger, "./kinit") is None
    assert any(("must be absolute" in msg for msg in lcm.output))


def test_475_kerberos_kinit_command_resolve_rejects_wrong_basename(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """absolute paths not named kinit are rejected"""
    with capture_logs("test_a2c", level="ERROR") as lcm:
        assert kerberos_kinit_command_resolve(logger, "/usr/bin/python3") is None
    assert any(("basename must be 'kinit'" in msg for msg in lcm.output))


def test_476_kerberos_kinit_command_resolve_rejects_bad_symlink_target(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """kinit symlink pointing at a non-kinit binary is rejected"""
    with TemporaryDirectory() as tmpdir:
        evil = os.path.join(tmpdir, "evil.sh")
        kinit_link = os.path.join(tmpdir, "kinit")
        with open(evil, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\n")
        os.symlink(evil, kinit_link)
        with capture_logs("test_a2c", level="ERROR") as lcm:
            assert kerberos_kinit_command_resolve(logger, kinit_link) is None
        assert any(("resolved basename must be one of" in msg for msg in lcm.output))


def test_477_enrollment_config_log(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """test enrollment_config_log()"""

    class myclass:
        pass

    myclass.foo = "foo_val"
    myclass.bar = "bar_val"
    myclass.foobar = "foobar_val"
    myclass.password = "password_val"
    myclass.secret = "secret_val"
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not enrollment_config_log(logger, myclass, ["foo", "bar"])
    assert (
        "INFO:test_a2c:Enrollment configuration: ['foobar: foobar_val']" in lcm.output
    )


def test_478_enrollment_config_log(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """test enrollment_config_log()"""

    class myclass:
        pass

    myclass.foo = "foo_val"
    myclass.bar = "bar_val"
    myclass.foobar = "foobar_val"
    myclass.password = "password_val"
    myclass.secret = "secret_val"
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not enrollment_config_log(logger, myclass, "failed to parse")
    assert (
        "ERROR:test_a2c:Enrollment configuration won't get logged due to: Configuration error"
        in lcm.output
    )


@patch("acme2certifier.acme_srv.helpers.utils.secrets.randbelow")
def test_510_radomize_parameter_list(
    mock_rand: MagicMock, logger: logging.Logger
) -> None:
    """test radomize_parameter_list()"""

    class myclass:
        pass

    myclass.foo = "foo1, foo2, foo2"
    myclass.bar = "bar1, bar2, bar3"
    radomize_parameter_list(logger, myclass, ["foo", "bar"])
    assert "foo2" == myclass.foo
    assert "bar2" == myclass.bar


@patch("acme2certifier.acme_srv.helpers.utils.secrets.randbelow")
def test_511_radomize_parameter_list(
    mock_rand: MagicMock, logger: logging.Logger
) -> None:
    """test radomize_parameter_list()"""

    class myclass:
        pass

    myclass.foo = "foo1, foo2, foo2"
    myclass.bar = "bar1, bar2, bar3"
    radomize_parameter_list(logger, myclass, ["foo1", "bar"])
    assert "foo1, foo2, foo2" == myclass.foo
    assert "bar2" == myclass.bar


@patch("acme2certifier.acme_srv.helpers.utils.secrets.randbelow")
def test_512_radomize_parameter_list(
    mock_rand: MagicMock, logger: logging.Logger
) -> None:
    """test radomize_parameter_list()"""

    class myclass:
        pass

    myclass.foo = "foo1"
    myclass.bar = "bar1"
    radomize_parameter_list(logger, myclass, ["foo1", "bar"])
    assert "foo1" == myclass.foo
    assert "bar1" == myclass.bar


def test_527_missing_required_keys(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """test handler_config_check() with missing required keys"""

    class DummyHandler(object):

        def __init__(self):
            self.vault_url = "url"
            self.vault_token = None

    dummy_handler = DummyHandler()
    required_keys = ["vault_url", "vault_token"]
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert (
            "vault_token parameter is missing in config file"
            == handler_config_check(logger, dummy_handler, required_keys)
        )
    assert (
        "ERROR:test_a2c:Configuration error: vault_token parameter is missing in config file"
        in lcm.output
    )


def test_528_all_required_keys_present(logger: logging.Logger) -> None:

    class DummyHandler(object):

        def __init__(self):
            self.vault_url = "url"
            self.vault_token = "token"
            self.another_param = "param"

    dummy_handler = DummyHandler()
    required_keys = ["vault_url", "vault_token"]
    assert not handler_config_check(logger, dummy_handler, required_keys)


def test_529_empty_config(logger: logging.Logger) -> None:

    class DummyHandler(object):

        def __init__(self):
            self.vault_url = "url"
            self.vault_token = "token"

    dummy_handler = DummyHandler()
    required_keys = []
    assert not handler_config_check(logger, dummy_handler, required_keys)


def test_647_kerberos_kinit_command_resolve_rejects_null_byte(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """paths containing a NUL byte are rejected"""
    with capture_logs("test_a2c", level="ERROR") as lcm:
        assert kerberos_kinit_command_resolve(logger, "/usr/bin/kinit\x00evil") is None
    assert any(("null byte in path" in msg for msg in lcm.output))
