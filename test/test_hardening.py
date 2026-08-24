# -*- coding: utf-8 -*-
"""Security hardening regression tests."""

from __future__ import annotations

import logging
import os
import sys
from unittest.mock import MagicMock, Mock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acme2certifier.acme_srv.authorization import Authorization, AuthorizationError
from acme2certifier.acme_srv.challenge import Challenge, ChallengeInfo
from acme2certifier.acme_srv.challenge_validators.base import ChallengeContext
from acme2certifier.acme_srv.challenge_validators.tkauth_validator import (
    NOT_IMPLEMENTED_MSG,
    TkauthChallengeValidator,
)
from acme2certifier.acme_srv.helpers.resource_ownership import (
    OWNERSHIP_DENIED_DETAIL,
    UNAUTHORIZED_TYPE,
    ownership_lookup_failed,
    ownership_unauthorized,
    resource_owner_matches,
)
from acme2certifier.acme_srv.helpers.security_gate import SECURITY_DISABLE_ACK_ENV
from acme2certifier.acme_srv.renewalinfo import Renewalinfo


class TestResourceOwnershipHelper:
    def test_001_owner_matches_equal_accounts(self) -> None:
        assert resource_owner_matches("acct-a", "acct-a") is True

    def test_002_owner_matches_different_accounts(self) -> None:
        assert resource_owner_matches("acct-a", "acct-b") is False

    def test_003_owner_matches_missing_requester(self) -> None:
        assert resource_owner_matches(None, "acct-a") is False
        assert resource_owner_matches("", "acct-a") is False

    def test_004_owner_matches_missing_owner(self) -> None:
        assert resource_owner_matches("acct-a", None) is False
        assert resource_owner_matches("acct-a", "") is False

    def test_005_unauthorized_tuple(self) -> None:
        assert ownership_unauthorized() == (
            403,
            UNAUTHORIZED_TYPE,
            OWNERSHIP_DENIED_DETAIL,
        )

    def test_006_lookup_failed_tuple(self) -> None:
        code, msg, _detail = ownership_lookup_failed()
        assert code == 500
        assert msg == "urn:ietf:params:acme:error:serverInternal"


class TestTkauthFailClosed:
    def test_007_validation_fails_closed_without_ack(self) -> None:
        logger = Mock(spec=logging.Logger)
        validator = TkauthChallengeValidator(logger)
        context = ChallengeContext(
            challenge_name="c1",
            token="tok",
            jwk_thumbprint="thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )
        with patch.dict(os.environ, {SECURITY_DISABLE_ACK_ENV: ""}, clear=False):
            result = validator.perform_validation(context)
        assert result.success is False
        assert result.invalid is True
        assert result.error_message == NOT_IMPLEMENTED_MSG

    def test_008_validation_succeeds_when_acknowledged(self) -> None:
        logger = logging.getLogger("test_hardening_tkauth")
        validator = TkauthChallengeValidator(logger)
        context = ChallengeContext(
            challenge_name="c1",
            token="tok",
            jwk_thumbprint="thumb",
            authorization_type="dns",
            authorization_value="example.com",
        )
        with patch.dict(os.environ, {SECURITY_DISABLE_ACK_ENV: "1"}, clear=False):
            result = validator.perform_validation(context)
        assert result.success is True
        assert result.invalid is False


class TestOrderResourceOwnership:
    @pytest.fixture
    def order(self):
        models_mock = MagicMock()
        with patch.dict(
            "sys.modules", {"acme2certifier.acme_srv.db_handler": models_mock}
        ):
            logging.basicConfig(level=logging.CRITICAL)
            logger = logging.getLogger("test_hardening_order")
            from acme2certifier.acme_srv.order import Order

            order_obj = Order(debug=True, server_name="http://srv", logger=logger)
            order_obj.message = MagicMock()
            order_obj.repository = MagicMock()
            order_obj.error_msg_dic = {
                "malformed": "urn:ietf:params:acme:error:malformed",
                "ordernotready": "urn:ietf:params:acme:error:orderNotReady",
                "serverinternal": "urn:ietf:params:acme:error:serverInternal",
                "unauthorized": UNAUTHORIZED_TYPE,
            }
            yield order_obj

    def test_009_account_order_request_denied(self, order) -> None:
        order.message.check.return_value = (
            200,
            None,
            None,
            {"url": "http://srv/acme/order/victim"},
            {},
            "attacker",
        )
        with patch.object(order, "_name_get", return_value="victim"), patch.object(
            order, "get_order_details", return_value={"status": "ready"}
        ), patch.object(
            order, "_get_order_account_name", return_value="victim-acct"
        ), patch.object(
            order, "_process_order_request"
        ) as mock_process:
            order.message.prepare_response.side_effect = lambda resp, status, **_: {
                **resp,
                **status,
            }
            result = order.parse_order_content("content")
        mock_process.assert_not_called()
        assert result["code"] == 403
        assert result["type"] == UNAUTHORIZED_TYPE

    def test_010_account_order_request_allowed(self, order) -> None:
        order.message.check.return_value = (
            200,
            None,
            None,
            {"url": "http://srv/acme/order/owner"},
            {},
            "owner-acct",
        )
        order.message.prepare_response.side_effect = lambda resp, status, **_: {
            **resp,
            **status,
        }
        with patch.object(order, "_name_get", return_value="owner"), patch.object(
            order, "get_order_details", return_value={"status": "ready"}
        ), patch.object(
            order, "_get_order_account_name", return_value="owner-acct"
        ), patch.object(
            order,
            "_process_order_request",
            return_value=(200, None, None, None),
        ), patch.object(
            order, "get_order_details", return_value={"status": "ready"}
        ):
            result = order.parse_order_content("content")
        assert result["code"] == 200

    def test_011_owner_lookup_unavailable_denied(self, order) -> None:
        order.message.check.return_value = (
            200,
            None,
            None,
            {"url": "http://srv/acme/order/victim"},
            {},
            "attacker",
        )
        order.message.prepare_response.side_effect = lambda resp, status, **_: {
            **resp,
            **status,
        }
        with patch.object(order, "_name_get", return_value="victim"), patch.object(
            order, "get_order_details", return_value={"status": "ready"}
        ), patch.object(order, "_get_order_account_name", return_value=None):
            result = order.parse_order_content("content")
        assert result["code"] == 403
        assert result["type"] == UNAUTHORIZED_TYPE


class TestCertificateResourceOwnership:
    @pytest.fixture
    def certificate(self):
        logging.basicConfig(level=logging.CRITICAL)
        logger = logging.getLogger("test_hardening_cert")
        from acme2certifier.acme_srv.certificate import Certificate

        cert = Certificate(debug=True, srv_name="http://srv", logger=logger)
        cert.message = MagicMock()
        cert.repository = MagicMock()
        cert.path_dic = {"cert_path": "/acme/cert/"}
        cert.err_msg_dic = {
            "malformed": "urn:ietf:params:acme:error:malformed",
            "serverinternal": "urn:ietf:params:acme:error:serverInternal",
            "unauthorized": UNAUTHORIZED_TYPE,
        }
        cert._prepare_certificate_response = MagicMock(
            side_effect=lambda resp, code, msg, detail, **_: {
                "code": code,
                "type": msg,
                "detail": detail,
                "data": resp,
            }
        )
        yield cert

    def test_012_account_certificate_download_denied(self, certificate) -> None:
        certificate._validate_certificate_request_message = MagicMock(
            return_value=(
                200,
                None,
                None,
                {"url": "http://srv/acme/cert/cert1"},
                {},
                "attacker",
            )
        )
        with patch.object(
            certificate, "_lookup_certificate_owner_account", return_value="victim"
        ), patch.object(certificate, "get_certificate_details") as mock_get:
            result = certificate.process_certificate_request("content")
        mock_get.assert_not_called()
        assert result["code"] == 403
        assert result["type"] == UNAUTHORIZED_TYPE

    def test_013_account_certificate_download_allowed(self, certificate) -> None:
        certificate._validate_certificate_request_message = MagicMock(
            return_value=(
                200,
                None,
                None,
                {"url": "http://srv/acme/cert/cert1"},
                {},
                "owner",
            )
        )
        with patch.object(
            certificate, "_lookup_certificate_owner_account", return_value="owner"
        ), patch.object(
            certificate,
            "get_certificate_details",
            return_value={"code": 200, "data": "pem"},
        ):
            result = certificate.process_certificate_request("content")
        assert result["code"] == 200


class TestChallengeResourceOwnership:
    @pytest.fixture
    def challenge(self):
        logging.basicConfig(level=logging.CRITICAL)
        logger = logging.getLogger("test_hardening_challenge")
        from acme2certifier.acme_srv.challenge import Challenge

        ch = Challenge(debug=True, srv_name="http://srv", logger=logger)
        ch.message = MagicMock()
        ch.repository = MagicMock()
        ch.err_msg_dic = {"malformed": "urn:ietf:params:acme:error:malformed"}
        ch._ensure_components_initialized = Mock()
        ch._extract_challenge_name_from_url = Mock(return_value="chal1")
        ch._create_error_response = MagicMock(
            side_effect=lambda code, msg, detail, **_: {
                "code": code,
                "type": msg,
                "detail": detail,
            }
        )
        ch.repository.get_challenge_by_name.return_value = ChallengeInfo(
            "chal1", "dns-01", "tok", "pending", "authz1", "dns", "example.com", "url"
        )
        yield ch

    def test_014_account_challenge_post_denied(self, challenge) -> None:
        challenge.message.check.return_value = (
            200,
            None,
            None,
            {"url": "http://srv/acme/chall/chal1"},
            {},
            "attacker",
        )
        challenge.repository.get_challenge_owner_account_name.return_value = "victim"
        with patch.object(
            challenge, "_handle_challenge_validation_request"
        ) as mock_handle:
            result = challenge.process_challenge_request("content")
        mock_handle.assert_not_called()
        assert result["code"] == 403

    def test_015_account_challenge_post_allowed(self, challenge) -> None:
        challenge.message.check.return_value = (
            200,
            None,
            None,
            {"url": "http://srv/acme/chall/chal1"},
            {},
            "owner",
        )
        challenge.repository.get_challenge_owner_account_name.return_value = "owner"
        with patch.object(
            challenge,
            "_handle_challenge_validation_request",
            return_value={"code": 200},
        ):
            result = challenge.process_challenge_request("content")
        assert result["code"] == 200


class TestAuthorizationResourceOwnership:
    @pytest.fixture
    def authorization(self):
        auth = Authorization(debug=True, srv_name="http://srv", logger=MagicMock())
        auth.config.expiry_check_disable = True
        auth.message = MagicMock()
        auth.repository = MagicMock()
        auth.business_logic = MagicMock()
        auth.business_logic.extract_authorization_name_from_url.return_value = "authz1"
        yield auth

    def test_016_account_authorization_post_denied(self, authorization) -> None:
        authorization.message.check.return_value = (
            200,
            "ok",
            "",
            {"url": "http://srv/acme/authz/authz1"},
            {},
            "attacker",
        )
        authorization.repository.find_authorization_by_name.return_value = {
            "order__account__name": "victim"
        }
        authorization.message.prepare_response.side_effect = lambda resp, status, **_: {
            **resp,
            **status,
        }
        with patch.object(authorization, "get_authorization_details") as mock_get:
            result = authorization.handle_post_request("content")
        mock_get.assert_not_called()
        assert result["code"] == 403
        assert result["type"] == UNAUTHORIZED_TYPE

    def test_017_account_authorization_post_allowed(self, authorization) -> None:
        authorization.message.check.return_value = (
            200,
            "ok",
            "",
            {"url": "http://srv/acme/authz/authz1"},
            {},
            "owner",
        )
        authorization.repository.find_authorization_by_name.return_value = {
            "order__account__name": "owner"
        }
        authorization.get_authorization_details = MagicMock(
            return_value={"status": "valid"}
        )
        authorization.message.prepare_response.side_effect = lambda resp, status, **_: {
            **resp,
            **status,
        }
        result = authorization.handle_post_request("content")
        assert result["code"] == 200

    def test_018_owner_lookup_db_error_returns_500(self, authorization) -> None:
        authorization.message.check.return_value = (
            200,
            "ok",
            "",
            {"url": "http://srv/acme/authz/authz1"},
            {},
            "owner",
        )
        authorization.repository.find_authorization_by_name.side_effect = (
            AuthorizationError("db")
        )
        authorization.message.prepare_response.side_effect = lambda resp, status, **_: {
            **resp,
            **status,
        }
        result = authorization.handle_post_request("content")
        assert result["code"] == 500


class TestRenewalinfoResourceOwnership:
    @pytest.fixture
    def renewalinfo(self):
        info = Renewalinfo(debug=True, srv_name="http://srv", logger=MagicMock())
        info.message = MagicMock()
        info.repository = MagicMock()
        yield info

    def test_019_account_replaced_update_denied(self, renewalinfo) -> None:
        renewalinfo.message.check.return_value = (
            200,
            None,
            None,
            None,
            {"certid": "cid", "replaced": True},
            "attacker",
        )
        renewalinfo.message.prepare_response.side_effect = lambda resp, status, **_: {
            **resp,
            "code": status["code"],
            "data": {
                "status": status["code"],
                "type": status.get("type"),
                "detail": status.get("detail"),
            },
            "header": {},
        }
        renewalinfo._lookup_certificate_by_renewalinfo = MagicMock(
            return_value={"name": "cert1", "order__account__name": "victim"}
        )
        result = renewalinfo.update("content")
        renewalinfo.repository.mark_certificate_replaced.assert_not_called()
        assert result["code"] == 403

    def test_020_account_replaced_update_allowed(self, renewalinfo) -> None:
        renewalinfo.message.check.return_value = (
            200,
            None,
            None,
            None,
            {"certid": "cid", "replaced": True},
            "owner",
        )
        renewalinfo._lookup_certificate_by_renewalinfo = MagicMock(
            return_value={"name": "cert1", "order__account__name": "owner"}
        )
        renewalinfo.repository.mark_certificate_replaced.return_value = True
        result = renewalinfo.update("content")
        assert result["code"] == 200
        renewalinfo.repository.mark_certificate_replaced.assert_called_once_with(
            "cert1"
        )
