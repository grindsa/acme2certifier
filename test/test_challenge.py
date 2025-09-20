#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for account.py"""
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import sys
import configparser
from unittest.mock import patch, MagicMock

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class FakeDBStore(object):
    """face DBStore class needed for mocking"""

    # pylint: disable=W0107, R0903
    pass


class TestACMEHandler(unittest.TestCase):
    """test class for challenges class"""

    acme = None

    def setUp(self):
        """setup unittest"""
        models_mock = MagicMock()
        models_mock.acme_srv.db_handler.DBstore.return_value = FakeDBStore
        modules = {"acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        import logging

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from acme_srv.challenge import Challenge

        self.challenge = Challenge(False, "http://tester.local", self.logger)

    @patch("acme_srv.challenge.generate_random_string")
    def test_001_challenge__new(self, mock_random):
        """test challenge generation"""
        mock_random.return_value = "foo"
        # self.order.dbstore.challenge_new.return_value = 1
        self.assertEqual(
            {
                "url": "http://tester.local/acme/chall/foo",
                "token": "token",
                "type": "mtype",
                "status": "pending",
            },
            self.challenge._new("authz_name", "mtype", "token"),
        )

    @patch("acme_srv.challenge.generate_random_string")
    def test_002_challenge__new(self, mock_random):
        """test challenge generation for tnauthlist challenge"""
        mock_random.return_value = "foo"
        # self.order.dbstore.challenge_new.return_value = 1
        self.assertEqual(
            {
                "url": "http://tester.local/acme/chall/foo",
                "token": "token",
                "type": "tkauth-01",
                "tkauth-type": "atc",
                "status": "pending",
            },
            self.challenge._new("authz_name", "tkauth-01", "token"),
        )

    @patch("acme_srv.challenge.generate_random_string")
    def test_003_challenge__new(self, mock_random):
        """test challenge generation for sectigo challenge"""
        mock_random.return_value = "foo"
        self.challenge.sectigo_sim = True
        # self.order.dbstore.challenge_new.return_value = 1
        self.assertEqual(
            {
                "url": "http://tester.local/acme/chall/foo",
                "type": "sectigo-email-01",
                "status": "valid",
            },
            self.challenge._new("authz_name", "sectigo-email-01", "token"),
        )

    @patch("acme_srv.challenge.generate_random_string")
    def test_004_challenge__new(self, mock_random):
        """test challenge generation challenge add throws exception"""
        mock_random.return_value = "foo"
        self.challenge.dbstore.challenge_add.side_effect = Exception("ex_new")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(self.challenge._new("authz_name", "tkauth-01", "token"))
        self.assertTrue(mock_random.called)
        self.assertIn(
            "CRITICAL:test_a2c:Database error: failed to add new challenge: ex_new, value: None, type: tkauth-01",
            lcm.output,
        )

    @patch("acme_srv.challenge.Challenge._email_send")
    @patch("acme_srv.challenge.generate_random_string")
    def test_005_challenge__new(self, mock_random, mock_send):
        """test challenge generation for email-reply-00 challenge"""
        mock_random.return_value = "foo"
        self.challenge.dbstore.challenge_add.side_effect = None
        self.challenge.email_address = "foo@bar.local"
        self.assertEqual(
            {
                "url": "http://tester.local/acme/chall/foo",
                "type": "email-reply-00",
                "status": "pending",
                "from": "foo@bar.local",
                "token": "token",
            },
            self.challenge._new("authz_name", "email-reply-00", "token"),
        )

    @patch("acme_srv.challenge.Challenge._new")
    def test_006_challenge_new_set(self, mock_challenge):
        """test generation of a challenge set"""
        mock_challenge.return_value = {"foo": "bar"}
        self.assertEqual(
            [{"foo": "bar"}, {"foo": "bar"}, {"foo": "bar"}],
            self.challenge.new_set("authz_name", "token"),
        )

    @patch("acme_srv.challenge.Challenge._new")
    def test_007_challenge_new_set(self, mock_challenge):
        """test generation of a challenge set for IPAddress type"""
        mock_challenge.return_value = {"foo": "bar"}
        self.assertEqual(
            [{"foo": "bar"}, {"foo": "bar"}],
            self.challenge.new_set("authz_name", "token", False, "ip"),
        )

    @patch("acme_srv.challenge.Challenge._new")
    def test_008_challenge_new_set(self, mock_challenge):
        """test generation of a challenge set with tnauth true"""
        mock_challenge.return_value = {"foo": "bar"}
        self.assertEqual(
            [{"foo": "bar"}], self.challenge.new_set("authz_name", "token", True)
        )

    @patch("acme_srv.challenge.Challenge._new")
    def test_009_challenge_new_set(self, mock_challenge):
        """test generation of a challenge set with empty challenge"""
        mock_challenge.side_effect = [{"foo1": "bar1"}, {}, {"foo3": "bar3"}]
        self.assertEqual(
            [{"foo1": "bar1"}, {"foo3": "bar3"}],
            self.challenge.new_set("authz_name", "token", False),
        )

    @patch("acme_srv.challenge.Challenge._new")
    def test_010_challenge_new_set(self, mock_challenge):
        """test generation of a challenge with sectigo_sim True"""
        mock_challenge.return_value = {"foo": "sectigo_sim"}
        self.challenge.sectigo_sim = True
        self.assertEqual(
            [{"foo": "sectigo_sim"}],
            self.challenge.new_set("authz_name", "token", False),
        )

    @patch("acme_srv.challenge.Challenge._new")
    def test_011_challenge_new_set(self, mock_challenge):
        """test generation of a challenge with email"""
        mock_challenge.return_value = {"foo": "bar"}
        self.challenge.email_identifier_support = True
        self.assertEqual(
            [{"foo": "bar"}],
            self.challenge.new_set(
                authz_name="authz_name",
                token="token",
                id_type="email",
                value="email@email.com",
            ),
        )
        mock_challenge.assert_called_with(
            authz_name="authz_name",
            mtype="email-reply-00",
            token="token",
            value="email@email.com",
        )

    @patch("acme_srv.challenge.Challenge._new")
    def test_012_challenge_new_set(self, mock_challenge):
        """test generation of a challenge with email"""
        mock_challenge.return_value = {"foo": "bar"}
        self.challenge.email_identifier_support = True
        self.assertEqual(
            [{"foo": "bar"}],
            self.challenge.new_set(
                authz_name="authz_name",
                token="token",
                id_type="dns",
                value="email@email.com",
            ),
        )
        mock_challenge.assert_called_with(
            authz_name="authz_name",
            mtype="email-reply-00",
            token="token",
            value="email@email.com",
        )

    @patch("acme_srv.challenge.Challenge._new")
    def test_013_challenge_new_set(self, mock_challenge):
        """test generation of a challenge with email"""
        mock_challenge.return_value = {"foo": "bar"}
        self.challenge.email_identifier_support = False
        self.assertEqual(
            [{"foo": "bar"}, {"foo": "bar"}, {"foo": "bar"}],
            self.challenge.new_set(
                authz_name="authz_name",
                token="token",
                id_type="dns",
                value="email@email.com",
            ),
        )
        mock_challenge.assert_called_with(
            authz_name="authz_name",
            mtype="tls-alpn-01",
            token="token",
            value="email@email.com",
        )

    def test_014_challenge__info(self):
        """test challenge.info()"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "token": "token",
            "type": "http-01",
            "status": "pending",
        }
        self.assertEqual(
            {"status": "pending", "token": "token", "type": "http-01"},
            self.challenge._info("foo"),
        )

    def test_015_challenge__info(self):
        """test challenge.info()  test no "status" field in"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "token": "token",
            "type": "http-01",
            "validated": "foo",
        }
        self.assertEqual(
            {"token": "token", "type": "http-01"}, self.challenge._info("foo")
        )

    def test_016_challenge__info(self):
        """test challenge.info()  test to pop "validated" key"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "token": "token",
            "type": "http-01",
            "status": "pending",
            "validated": "foo",
        }
        self.assertEqual(
            {"status": "pending", "token": "token", "type": "http-01"},
            self.challenge._info("foo"),
        )

    def test_017_challenge__info(self):
        """test challenge.info()  test to pop validated key no "status" and "validated" in"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "token": "token",
            "type": "http-01",
        }
        self.assertEqual(
            {"token": "token", "type": "http-01"}, self.challenge._info("foo")
        )

    def test_018_challenge__info(self):
        """test challenge.info()  test to pop "validated" key"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "token": "token",
            "type": "http-01",
            "status": "valid",
            "validated": "foo",
        }
        self.assertEqual(
            {"status": "valid", "token": "token", "type": "http-01"},
            self.challenge._info("foo"),
        )

    def test_019_challenge__info(self):
        """test challenge.info()  test to pop "validated" key"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "token": "token",
            "type": "http-01",
            "status": "valid",
            "validated": 1543640400,
        }
        self.assertEqual(
            {
                "status": "valid",
                "token": "token",
                "type": "http-01",
                "validated": "2018-12-01T05:00:00Z",
            },
            self.challenge._info("foo"),
        )

    def test_020_challenge__info(self):
        """test challenge.info()  test to pop "validated" key"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "token": "token",
            "type": "http-01",
            "status": "valid",
            "validated": 1543640400,
        }
        self.challenge.email_identifier_support = True
        self.challenge.email_address = "email@email.com"
        self.assertEqual(
            {
                "from": "email@email.com",
                "status": "valid",
                "token": "token",
                "type": "http-01",
                "validated": "2018-12-01T05:00:00Z",
            },
            self.challenge._info("foo"),
        )

    @patch("acme_srv.nonce.Nonce.generate_and_add")
    @patch("acme_srv.message.Message.check")
    def test_021_challenge_parse(self, mock_mcheck, mock_nnonce):
        """Challenge.parse() failed bcs. message check returns an error"""
        mock_mcheck.return_value = (
            400,
            "urn:ietf:params:acme:error:malformed",
            "detail",
            "protected",
            "payload",
            "account_name",
        )
        mock_nnonce.return_value = "new_nonce"
        self.assertEqual(
            {
                "code": 400,
                "header": {"Replay-Nonce": "new_nonce"},
                "data": {
                    "detail": "detail",
                    "type": "urn:ietf:params:acme:error:malformed",
                    "status": 400,
                },
            },
            self.challenge.parse("content"),
        )
        self.assertTrue(mock_nnonce.called)

    @patch("acme_srv.nonce.Nonce.generate_and_add")
    @patch("acme_srv.message.Message.check")
    def test_022_challenge_parse(self, mock_mcheck, mock_nnonce):
        """Challenge.parse() failed message check returns ok but no url in protected"""
        mock_mcheck.return_value = (
            200,
            "urn:ietf:params:acme:error:malformed",
            "detail",
            {"foo": "bar"},
            "payload",
            "account_name",
        )
        mock_nnonce.return_value = "new_nonce"
        self.assertEqual(
            {
                "code": 400,
                "header": {"Replay-Nonce": "new_nonce"},
                "data": {
                    "detail": "url missing in protected header",
                    "type": "urn:ietf:params:acme:error:malformed",
                    "status": 400,
                },
            },
            self.challenge.parse("content"),
        )
        self.assertTrue(mock_nnonce.called)

    @patch("acme_srv.nonce.Nonce.generate_and_add")
    @patch("acme_srv.challenge.Challenge._name_get")
    @patch("acme_srv.message.Message.check")
    def test_023_challenge_parse(self, mock_mcheck, mock_cname, mock_nnonce):
        """Challenge.parse() message check returns ok with tnauhlist enabled failed tnauth check"""
        self.challenge.tnauthlist_support = True
        mock_mcheck.return_value = (
            200,
            "message",
            "detail",
            {"url": "foo"},
            {},
            "account_name",
        )
        mock_nnonce.return_value = "new_nonce"
        mock_cname.return_value = None
        self.assertEqual(
            {
                "code": 400,
                "data": {
                    "detail": "could not get challenge",
                    "type": "urn:ietf:params:acme:error:malformed",
                    "status": 400,
                },
                "header": {"Replay-Nonce": "new_nonce"},
            },
            self.challenge.parse("content"),
        )
        self.assertTrue(mock_nnonce.called)

    @patch("acme_srv.nonce.Nonce.generate_and_add")
    @patch("acme_srv.challenge.Challenge._info")
    @patch("acme_srv.challenge.Challenge._name_get")
    @patch("acme_srv.message.Message.check")
    def test_024_challenge_parse(self, mock_mcheck, mock_cname, mock_info, mock_nnonce):
        """Challenge.parse() message check returns challenge.info() failed"""
        self.challenge.tnauthlist_support = True
        mock_mcheck.return_value = (
            200,
            "message",
            "detail",
            {"url": "foo"},
            {},
            "account_name",
        )
        mock_nnonce.return_value = "new_nonce"
        mock_cname.return_value = "foo"
        mock_info.return_value = {}
        self.assertEqual(
            {
                "code": 400,
                "data": {
                    "detail": "invalid challenge: foo",
                    "type": "urn:ietf:params:acme:error:malformed",
                    "status": 400,
                },
                "header": {"Replay-Nonce": "new_nonce"},
            },
            self.challenge.parse("content"),
        )
        self.assertTrue(mock_nnonce.called)

    @patch("acme_srv.nonce.Nonce.generate_and_add")
    @patch("acme_srv.challenge.Challenge._validate_tnauthlist_payload")
    @patch("acme_srv.challenge.Challenge._info")
    @patch("acme_srv.challenge.Challenge._name_get")
    @patch("acme_srv.message.Message.check")
    def test_025_challenge_parse(
        self, mock_mcheck, mock_cname, mock_info, mock_tnauth, mock_nnonce
    ):
        """Challenge.parse() with tnauhlist enabled and failed tnauth check"""
        self.challenge.tnauthlist_support = True
        mock_mcheck.return_value = (
            200,
            "message",
            "detail",
            {"url": "foo"},
            {},
            "account_name",
        )
        mock_nnonce.return_value = "new_nonce"
        mock_cname.return_value = "foo"
        mock_info.return_value = {"foo": "bar"}
        mock_tnauth.return_value = (400, "foo", "bar")
        self.assertEqual(
            {
                "code": 400,
                "data": {"detail": "bar", "type": "foo", "status": 400},
                "header": {"Replay-Nonce": "new_nonce"},
            },
            self.challenge.parse("content"),
        )
        self.assertTrue(mock_nnonce.called)

    @patch("acme_srv.nonce.Nonce.generate_and_add")
    @patch("acme_srv.challenge.Challenge._validate_tnauthlist_payload")
    @patch("acme_srv.challenge.Challenge._info")
    @patch("acme_srv.challenge.Challenge._name_get")
    @patch("acme_srv.message.Message.check")
    def test_026_challenge_parse(
        self, mock_mcheck, mock_cname, mock_cinfo, mock_tnauth, mock_nnonce
    ):
        """Challenge.parse() successful with TNauthlist enabled"""
        self.challenge.tnauthlist_support = True
        mock_mcheck.return_value = (
            200,
            "urn:ietf:params:acme:error:malformed",
            "detail",
            {"url": "bar"},
            "payload",
            "account_name",
        )
        mock_cname.return_value = "foo"
        mock_cinfo.return_value = {"challenge_foo": "challenge_bar"}
        mock_tnauth.return_value = (200, "foo", "bar")
        mock_nnonce.return_value = "new_nonce"
        self.assertEqual(
            {
                "code": 200,
                "header": {
                    "Link": '<http://tester.local/acme/authz/>;rel="up"',
                    "Replay-Nonce": "new_nonce",
                },
                "data": {"challenge_foo": "challenge_bar", "url": "bar"},
            },
            self.challenge.parse("content"),
        )
        self.assertTrue(mock_tnauth.called)

    @patch("acme_srv.nonce.Nonce.generate_and_add")
    @patch("acme_srv.challenge.Challenge._validate_tnauthlist_payload")
    @patch("acme_srv.challenge.Challenge._info")
    @patch("acme_srv.challenge.Challenge._name_get")
    @patch("acme_srv.message.Message.check")
    def test_027_challenge_parse(
        self, mock_mcheck, mock_cname, mock_cinfo, mock_tnauth, mock_nnonce
    ):
        """Challenge.parse() successful with TNauthlist disabled"""
        self.challenge.tnauthlist_support = False
        mock_mcheck.return_value = (
            200,
            "urn:ietf:params:acme:error:malformed",
            "detail",
            {"url": "bar"},
            "payload",
            "account_name",
        )
        mock_cname.return_value = "foo"
        mock_cinfo.return_value = {"challenge_foo": "challenge_bar"}
        mock_tnauth.return_value = (200, "foo", "bar")
        mock_nnonce.return_value = "new_nonce"
        self.assertEqual(
            {
                "code": 200,
                "header": {
                    "Link": '<http://tester.local/acme/authz/>;rel="up"',
                    "Replay-Nonce": "new_nonce",
                },
                "data": {"challenge_foo": "challenge_bar", "url": "bar"},
            },
            self.challenge.parse("content"),
        )
        self.assertFalse(mock_tnauth.called)

    @patch("acme_srv.nonce.Nonce.generate_and_add")
    @patch("acme_srv.challenge.Challenge._validate_tnauthlist_payload")
    @patch("acme_srv.challenge.Challenge._info")
    @patch("acme_srv.challenge.Challenge._name_get")
    @patch("acme_srv.message.Message.check")
    def test_028_challenge_parse(
        self, mock_mcheck, mock_cname, mock_cinfo, mock_tnauth, mock_nnonce
    ):
        """Challenge.parse() successful with valid status"""
        self.challenge.tnauthlist_support = False
        mock_mcheck.return_value = (
            200,
            "urn:ietf:params:acme:error:malformed",
            "detail",
            {"url": "bar"},
            "payload",
            "account_name",
        )
        mock_cname.return_value = "foo"
        mock_cinfo.return_value = {"challenge_foo": "challenge_bar", "status": "valid"}
        mock_tnauth.return_value = (200, "foo", "bar")
        mock_nnonce.return_value = "new_nonce"
        self.assertEqual(
            {
                "code": 200,
                "header": {
                    "Link": '<http://tester.local/acme/authz/>;rel="up"',
                    "Replay-Nonce": "new_nonce",
                },
                "data": {
                    "challenge_foo": "challenge_bar",
                    "url": "bar",
                    "status": "valid",
                },
            },
            self.challenge.parse("content"),
        )
        self.assertFalse(mock_tnauth.called)

    @patch("acme_srv.challenge.Challenge._validate")
    @patch("acme_srv.nonce.Nonce.generate_and_add")
    @patch("acme_srv.challenge.Challenge._validate_tnauthlist_payload")
    @patch("acme_srv.challenge.Challenge._info")
    @patch("acme_srv.challenge.Challenge._name_get")
    @patch("acme_srv.message.Message.check")
    def test_029_challenge_parse(
        self,
        mock_mcheck,
        mock_cname,
        mock_cinfo,
        mock_tnauth,
        mock_nnonce,
        mock_validate,
    ):
        """Challenge.parse() successful with some status and statusupdate"""
        self.challenge.tnauthlist_support = False
        mock_mcheck.return_value = (
            200,
            "urn:ietf:params:acme:error:malformed",
            "detail",
            {"url": "bar"},
            "payload",
            "account_name",
        )
        mock_cname.return_value = "foo"
        mock_cinfo.side_effect = [
            {"challenge_foo": "challenge_bar", "status": "status"},
            {"challenge_foo": "challenge_bar", "status": "new"},
        ]
        mock_tnauth.return_value = (200, "foo", "bar")
        mock_nnonce.return_value = "new_nonce"
        self.assertEqual(
            {
                "code": 200,
                "header": {
                    "Link": '<http://tester.local/acme/authz/>;rel="up"',
                    "Replay-Nonce": "new_nonce",
                },
                "data": {
                    "challenge_foo": "challenge_bar",
                    "url": "bar",
                    "status": "new",
                },
            },
            self.challenge.parse("content"),
        )
        self.assertFalse(mock_tnauth.called)
        self.assertTrue(mock_validate.called)

    def test_030_challenge__validate_tnauthlist_payload(self):
        """Challenge.validate_tnauthlist_payload with empty challenge_dic"""
        payload = {"foo": "bar"}
        challenge_dic = {}
        self.assertEqual(
            (400, "urn:ietf:params:acme:error:malformed", "invalid challenge: {}"),
            self.challenge._validate_tnauthlist_payload(payload, challenge_dic),
        )

    def test_031_challenge__validate_tnauthlist_payload(self):
        """Challenge.validate_tnauthlist_payload with empty challenge_dic"""
        payload = {}
        challenge_dic = {"type": "foo"}
        self.assertEqual(
            (200, None, None),
            self.challenge._validate_tnauthlist_payload(payload, challenge_dic),
        )

    def test_032_challenge__validate_tnauthlist_payload(self):
        """Challenge.validate_tnauthlist_payload without atc claim"""
        payload = {}
        challenge_dic = {"type": "tkauth-01"}
        self.assertEqual(
            (400, "urn:ietf:params:acme:error:malformed", "atc claim is missing"),
            self.challenge._validate_tnauthlist_payload(payload, challenge_dic),
        )

    def test_033_challenge__validate_tnauthlist_payload(self):
        """Challenge.validate_tnauthlist_payload with empty atc claim"""
        payload = {"atc": None}
        challenge_dic = {"type": "tkauth-01"}
        self.assertEqual(
            (400, "urn:ietf:params:acme:error:malformed", "SPC token is missing"),
            self.challenge._validate_tnauthlist_payload(payload, challenge_dic),
        )

    def test_034_challenge__validate_tnauthlist_payload(self):
        """Challenge.validate_tnauthlist_payload with '' atc claim"""
        payload = {"atc": ""}
        challenge_dic = {"type": "tkauth-01"}
        self.assertEqual(
            (400, "urn:ietf:params:acme:error:malformed", "SPC token is missing"),
            self.challenge._validate_tnauthlist_payload(payload, challenge_dic),
        )

    def test_035_challenge__validate_tnauthlist_payload(self):
        """Challenge.validate_tnauthlist_payload with spc token in atc claim"""
        payload = {"atc": "a"}
        challenge_dic = {"type": "tkauth-01"}
        self.assertEqual(
            (200, None, None),
            self.challenge._validate_tnauthlist_payload(payload, challenge_dic),
        )

    @patch("acme_srv.challenge.fqdn_resolve")
    @patch("acme_srv.challenge.url_get")
    def test_036_challenge__validate_http_challenge(self, mock_url, mock_resolve):
        """test Chalölenge.validate_http_challenge() with a wrong challenge"""
        mock_url.return_value = "foo"
        mock_resolve.return_value = ("foo", False)
        self.assertEqual(
            (False, False),
            self.challenge._validate_http_challenge(
                "cert_name", "dns", "fqdn", "token", "jwk_thumbprint"
            ),
        )

    @patch("acme_srv.challenge.fqdn_resolve")
    @patch("acme_srv.challenge.url_get")
    def test_037_challenge__validate_http_challenge(self, mock_url, mock_resolve):
        """test Chalölenge.validate_http_challenge() with a correct challenge"""
        mock_url.return_value = "token.jwk_thumbprint"
        mock_resolve.return_value = ("foo", False)
        self.assertEqual(
            (True, False),
            self.challenge._validate_http_challenge(
                "cert_name", "dns", "fqdn", "token", "jwk_thumbprint"
            ),
        )

    @patch("acme_srv.challenge.proxy_check")
    @patch("acme_srv.challenge.fqdn_resolve")
    @patch("acme_srv.challenge.url_get")
    def test_038_challenge__validate_http_challenge(
        self, mock_url, mock_resolve, mock_proxy
    ):
        """test Chalölenge.validate_http_challenge() with a correct challenge"""
        mock_url.return_value = "token.jwk_thumbprint"
        self.challenge.proxy_server_list = "proxy_server_list"
        mock_proxy.return_value = "proxy"
        mock_resolve.return_value = ("foo", False)
        self.assertEqual(
            (True, False),
            self.challenge._validate_http_challenge(
                "cert_name", "dns", "fqdn", "token", "jwk_thumbprint"
            ),
        )

    @patch("acme_srv.challenge.fqdn_resolve")
    @patch("acme_srv.challenge.url_get")
    def test_039_challenge__validate_http_challenge(self, mock_url, mock_resolve):
        """test Chalölenge.validate_http_challenge() without response"""
        mock_url.return_value = None
        mock_resolve.return_value = ("foo", False)
        self.assertEqual(
            (False, False),
            self.challenge._validate_http_challenge(
                "cert_name", "dns", "fqdn", "token", "jwk_thumbprint"
            ),
        )

    @patch("acme_srv.challenge.fqdn_resolve")
    @patch("acme_srv.challenge.url_get")
    def test_040_challenge__validate_http_challenge(self, mock_url, mock_resolve):
        """test Challenge.validate_http_challenge() failed with NX-domain error"""
        mock_url.return_value = None
        mock_resolve.return_value = (None, True)
        self.assertEqual(
            (False, True),
            self.challenge._validate_http_challenge(
                "cert_name", "dns", "fqdn", "token", "jwk_thumbprint"
            ),
        )

    @patch("acme_srv.challenge.fqdn_resolve")
    @patch("acme_srv.challenge.url_get")
    def test_041_challenge__validate_http_challenge(self, mock_url, mock_resolve):
        """test Chalölenge.validate_http_challenge() failed with NX-domain error - non existing case but to be tested"""
        mock_url.return_value = "foo"
        mock_resolve.return_value = ("foo", True)
        self.assertEqual(
            (False, True),
            self.challenge._validate_http_challenge(
                "cert_name", "dns", "fqdn", "token", "jwk_thumbprint"
            ),
        )

    @patch("acme_srv.challenge.fqdn_resolve")
    @patch("acme_srv.challenge.url_get")
    def test_042_challenge__validate_http_challenge(self, mock_url, mock_resolve):
        """test Chalölenge.validate_http_challenge() with a correct challenge ip address"""
        mock_url.return_value = "token.jwk_thumbprint"
        mock_resolve.return_value = ("foo", False)
        self.assertEqual(
            (True, False),
            self.challenge._validate_http_challenge(
                "cert_name", "ip", "127.0.0.1", "token", "jwk_thumbprint"
            ),
        )
        self.assertFalse(mock_resolve.called)

    @patch("acme_srv.challenge.fqdn_resolve")
    @patch("acme_srv.challenge.url_get")
    def test_043_challenge__validate_http_challenge(self, mock_url, mock_resolve):
        """test Chalölenge.validate_http_challenge() with unknown type"""
        mock_url.return_value = "token.jwk_thumbprint"
        mock_resolve.return_value = ("foo", False)
        self.assertEqual(
            (False, True),
            self.challenge._validate_http_challenge(
                "cert_name", "unk", "127.0.0.1", "token", "jwk_thumbprint"
            ),
        )
        self.assertFalse(mock_resolve.called)
        self.assertFalse(mock_url.called)

    @patch("acme_srv.challenge.fqdn_resolve")
    @patch("acme_srv.challenge.sha256_hash")
    @patch("acme_srv.challenge.b64_url_encode")
    @patch("acme_srv.challenge.txt_get")
    def test_044_challenge__validate_dns_challenge(
        self, mock_dns, mock_code, mock_hash, mock_resolve
    ):
        """test Chalölenge.validate_dns_challenge() with incorrect response"""
        mock_dns.return_value = ["foo"]
        mock_code.return_value = "bar"
        mock_hash.return_value = "hash"
        mock_resolve.return_value = ("foo", False)
        self.assertEqual(
            (False, False),
            self.challenge._validate_dns_challenge(
                "cert_name", "dns", "fqdn", "token", "jwk_thumbprint"
            ),
        )

    @patch("acme_srv.challenge.fqdn_resolve")
    @patch("acme_srv.challenge.sha256_hash")
    @patch("acme_srv.challenge.b64_url_encode")
    @patch("acme_srv.challenge.txt_get")
    def test_045_challenge__validate_dns_challenge(
        self, mock_dns, mock_code, mock_hash, mock_resolve
    ):
        """test Chalölenge.validate_dns_challenge() with correct response"""
        mock_dns.return_value = ["foo"]
        mock_code.return_value = "foo"
        mock_hash.return_value = "hash"
        mock_resolve.return_value = ("foo", False)
        self.assertEqual(
            (True, False),
            self.challenge._validate_dns_challenge(
                "cert_name", "dns", "fqdn", "token", "jwk_thumbprint"
            ),
        )

    @patch("acme_srv.challenge.fqdn_resolve")
    @patch("acme_srv.challenge.sha256_hash")
    @patch("acme_srv.challenge.b64_url_encode")
    @patch("acme_srv.challenge.txt_get")
    def test_046_challenge__validate_dns_challenge(
        self, mock_dns, mock_code, mock_hash, mock_resolve
    ):
        """test Challenge.validate_dns_challenge() with invalid response - obsolete"""
        mock_dns.return_value = ["foo"]
        mock_code.return_value = "bar"
        mock_hash.return_value = "hash"
        mock_resolve.return_value = (None, True)
        self.assertEqual(
            (False, False),
            self.challenge._validate_dns_challenge(
                "cert_name", "dns", "fqdn", "token", "jwk_thumbprint"
            ),
        )

    @patch("acme_srv.challenge.fqdn_resolve")
    @patch("acme_srv.challenge.sha256_hash")
    @patch("acme_srv.challenge.b64_url_encode")
    @patch("acme_srv.challenge.txt_get")
    def test_047_challenge__validate_dns_challenge(
        self, mock_dns, mock_code, mock_hash, mock_resolve
    ):
        """test Challenge.validate_dns_challenge() with invalid but correct fqdn returned - obsolete"""
        mock_dns.return_value = ["foo"]
        mock_code.return_value = "foo"
        mock_hash.return_value = "hash"
        mock_resolve.return_value = ("foo", True)
        self.assertEqual(
            (True, False),
            self.challenge._validate_dns_challenge(
                "cert_name", "dns", "fqdn", "token", "jwk_thumbprint"
            ),
        )

    def test_048_challenge__validate_tkauth_challenge(self):
        """test Chalölenge.validate_tkauth_challenge()"""
        self.assertEqual(
            (True, False),
            self.challenge._validate_tkauth_challenge(
                "cert_name", "type", "fqdn", "token", "jwk_thumbprint", "payload"
            ),
        )

    @patch("time.sleep")
    def test_049_challenge__check(self, mock_sleep):
        """challenge check with incorrect challenge-dictionary"""
        # self.challenge.dbstore.challenge_lookup.return_value = {'token' : 'token', 'type' : 'http-01', 'status' : 'pending'}
        self.challenge.dbstore.challenge_lookup.return_value = {}
        self.assertEqual((False, False), self.challenge._check("name", "payload"))

    @patch("time.sleep")
    def test_050_challenge__check(self, mock_sleep):
        """challenge check with without jwk return"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "authorization__value": "authorization__value",
            "type": "type",
            "token": "token",
            "authorization__order__account__name": "authorization__order__account__name",
        }
        self.challenge.dbstore.jwk_load.return_value = None
        self.assertEqual((False, False), self.challenge._check("name", "payload"))

    @patch("time.sleep")
    @patch("acme_srv.challenge.Challenge._validate_alpn_challenge")
    @patch("acme_srv.challenge.jwk_thumbprint_get")
    def test_051_challenge__check(self, mock_jwk, mock_chall, mock_sleep):
        """challenge check with with failed tls-alpn challenge - for loop returns data during 1st iteration"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "authorization__type": "authorization__type",
            "authorization__value": "authorization__value",
            "type": "tls-alpn-01",
            "token": "token",
            "authorization__order__account__name": "authorization__order__account__name",
        }
        self.challenge.dbstore.jwk_load.return_value = "pub_key"
        mock_chall.side_effect = [(False, "foo")]
        mock_jwk.return_value = "jwk_thumbprint"
        self.assertEqual((False, "foo"), self.challenge._check("name", "payload"))
        self.assertTrue(mock_chall.called)

    @patch("time.sleep")
    @patch("acme_srv.challenge.Challenge._validate_alpn_challenge")
    @patch("acme_srv.challenge.jwk_thumbprint_get")
    def test_052_challenge__check(self, mock_jwk, mock_chall, mock_sleep):
        """challenge check with with failed tls-alpn challenge - - for loop returns data during 2nd iteration"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "authorization__type": "authorization__type",
            "authorization__value": "authorization__value",
            "type": "tls-alpn-01",
            "token": "token",
            "authorization__order__account__name": "authorization__order__account__name",
        }
        self.challenge.dbstore.jwk_load.return_value = "pub_key"
        mock_chall.side_effect = [(False, False), (False, "foo")]
        mock_jwk.return_value = "jwk_thumbprint"
        self.assertEqual((False, "foo"), self.challenge._check("name", "payload"))
        self.assertTrue(mock_chall.called)

    @patch("time.sleep")
    @patch("acme_srv.challenge.Challenge._validate_alpn_challenge")
    @patch("acme_srv.challenge.jwk_thumbprint_get")
    def test_053_challenge__check(self, mock_jwk, mock_chall, mock_sleep):
        """challenge check with with failed tls-alpn challenge - - for loop returns data during 6th iteration"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "authorization__type": "authorization__type",
            "authorization__value": "authorization__value",
            "type": "tls-alpn-01",
            "token": "token",
            "authorization__order__account__name": "authorization__order__account__name",
        }
        self.challenge.dbstore.jwk_load.return_value = "pub_key"
        mock_chall.side_effect = [
            (False, False),
            (False, False),
            (False, False),
            (False, False),
            (False, False),
            (False, "foo"),
        ]
        mock_jwk.return_value = "jwk_thumbprint"
        self.assertEqual((False, False), self.challenge._check("name", "payload"))
        self.assertTrue(mock_chall.called)

    @patch("time.sleep")
    @patch("acme_srv.challenge.Challenge._validate_alpn_challenge")
    @patch("acme_srv.challenge.jwk_thumbprint_get")
    def test_054_challenge__check(self, mock_jwk, mock_chall, mock_sleep):
        """challenge check with with succ tls-alpn challenge"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "authorization__type": "authorization__type",
            "authorization__value": "authorization__value",
            "type": "tls-alpn-01",
            "token": "token",
            "authorization__order__account__name": "authorization__order__account__name",
        }
        self.challenge.dbstore.jwk_load.return_value = "pub_key"
        mock_chall.side_effect = [(True, "foo")]
        mock_jwk.return_value = "jwk_thumbprint"
        self.assertEqual((True, "foo"), self.challenge._check("name", "payload"))
        self.assertTrue(mock_chall.called)

    @patch("time.sleep")
    @patch("acme_srv.challenge.Challenge._validate_http_challenge")
    @patch("acme_srv.challenge.jwk_thumbprint_get")
    def test_055_challenge__check(self, mock_jwk, mock_chall, mock_sleep):
        """challenge check with with failed http challenge - for loop returns data during 1st iteration"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "authorization__type": "authorization__type",
            "authorization__value": "authorization__value",
            "type": "http-01",
            "token": "token",
            "authorization__order__account__name": "authorization__order__account__name",
        }
        self.challenge.dbstore.jwk_load.return_value = "pub_key"
        mock_chall.side_effect = [(False, "foo")]
        mock_jwk.return_value = "jwk_thumbprint"
        self.assertEqual((False, "foo"), self.challenge._check("name", "payload"))

    @patch("time.sleep")
    @patch("acme_srv.challenge.Challenge._validate_http_challenge")
    @patch("acme_srv.challenge.jwk_thumbprint_get")
    def test_056_challenge__check(self, mock_jwk, mock_chall, mock_sleep):
        """challenge check with with failed http challenge - for loop returns data during 2nd iteration"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "authorization__type": "authorization__type",
            "authorization__value": "authorization__value",
            "type": "http-01",
            "token": "token",
            "authorization__order__account__name": "authorization__order__account__name",
        }
        self.challenge.dbstore.jwk_load.return_value = "pub_key"
        mock_chall.side_effect = [(False, False), (False, "foo")]
        mock_jwk.return_value = "jwk_thumbprint"
        self.assertEqual((False, "foo"), self.challenge._check("name", "payload"))

    @patch("time.sleep")
    @patch("acme_srv.challenge.Challenge._validate_http_challenge")
    @patch("acme_srv.challenge.jwk_thumbprint_get")
    def test_057_challenge__check(self, mock_jwk, mock_chall, mock_sleep):
        """challenge check with with succ http challenge - for loop returns data during 1st iteration"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "authorization__type": "authorization__type",
            "authorization__value": "authorization__value",
            "type": "http-01",
            "token": "token",
            "authorization__order__account__name": "authorization__order__account__name",
        }
        self.challenge.dbstore.jwk_load.return_value = "pub_key"
        mock_chall.side_effect = [(True, "foo")]
        mock_jwk.return_value = "jwk_thumbprint"
        self.assertEqual((True, "foo"), self.challenge._check("name", "payload"))

    @patch("time.sleep")
    @patch("acme_srv.challenge.Challenge._validate_http_challenge")
    @patch("acme_srv.challenge.jwk_thumbprint_get")
    def test_058_challenge__check(self, mock_jwk, mock_chall, mock_sleep):
        """challenge check with with succ http challenge - for loop returns data during 2nd iteration"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "authorization__type": "authorization__type",
            "authorization__value": "authorization__value",
            "type": "http-01",
            "token": "token",
            "authorization__order__account__name": "authorization__order__account__name",
        }
        self.challenge.dbstore.jwk_load.return_value = "pub_key"
        mock_chall.side_effect = [(False, False), (True, "foo")]
        mock_jwk.return_value = "jwk_thumbprint"
        self.assertEqual((True, "foo"), self.challenge._check("name", "payload"))

    @patch("time.sleep")
    @patch("acme_srv.challenge.Challenge._validate_dns_challenge")
    @patch("acme_srv.challenge.jwk_thumbprint_get")
    def test_059_challenge__check(self, mock_jwk, mock_chall, mock_sleep):
        """challenge check with with failed dns challenge  - for loop returns data during 1st iteration"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "authorization__type": "authorization__type",
            "authorization__value": "authorization__value",
            "type": "dns-01",
            "token": "token",
            "authorization__order__account__name": "authorization__order__account__name",
        }
        self.challenge.dbstore.jwk_load.return_value = "pub_key"
        mock_chall.side_effect = [(True, "foo")]
        mock_jwk.return_value = "jwk_thumbprint"
        self.assertEqual((True, "foo"), self.challenge._check("name", "payload"))

    @patch("time.sleep")
    @patch("acme_srv.challenge.Challenge._validate_dns_challenge")
    @patch("acme_srv.challenge.jwk_thumbprint_get")
    def test_060_challenge__check(self, mock_jwk, mock_chall, mock_sleep):
        """challenge check with with failed dns challenge  - for loop returns data during 2nd iteration"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "authorization__type": "authorization__type",
            "authorization__value": "authorization__value",
            "type": "dns-01",
            "token": "token",
            "authorization__order__account__name": "authorization__order__account__name",
        }
        self.challenge.dbstore.jwk_load.return_value = "pub_key"
        mock_chall.side_effect = [(False, False), (True, "foo")]
        mock_jwk.return_value = "jwk_thumbprint"
        self.assertEqual((True, "foo"), self.challenge._check("name", "payload"))

    @patch("time.sleep")
    @patch("acme_srv.challenge.Challenge._validate_dns_challenge")
    @patch("acme_srv.challenge.jwk_thumbprint_get")
    def test_061_challenge__check(self, mock_jwk, mock_chall, mock_sleep):
        """challenge check with with succ http challenge - for loop returns data during 1st iteration"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "authorization__type": "authorization__type",
            "authorization__value": "authorization__value",
            "type": "dns-01",
            "token": "token",
            "authorization__order__account__name": "authorization__order__account__name",
        }
        self.challenge.dbstore.jwk_load.return_value = "pub_key"
        mock_chall.side_effect = [(True, "foo")]
        mock_jwk.return_value = "jwk_thumbprint"
        self.assertTrue((False, "foo"), self.challenge._check("name", "payload"))

    @patch("time.sleep")
    @patch("acme_srv.challenge.Challenge._validate_dns_challenge")
    @patch("acme_srv.challenge.jwk_thumbprint_get")
    def test_062_challenge__check(self, mock_jwk, mock_chall, mock_sleep):
        """challenge check with with succ http challenge  - for loop returns data during 2nd iteration"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "authorization__type": "authorization__type",
            "authorization__value": "authorization__value",
            "type": "dns-01",
            "token": "token",
            "authorization__order__account__name": "authorization__order__account__name",
        }
        self.challenge.dbstore.jwk_load.return_value = "pub_key"
        mock_chall.side_effect = [(False, False), (True, "foo")]
        mock_jwk.return_value = "jwk_thumbprint"
        self.assertTrue((False, "foo"), self.challenge._check("name", "payload"))

    @patch("time.sleep")
    @patch("acme_srv.challenge.Challenge._validate_tkauth_challenge")
    @patch("acme_srv.challenge.jwk_thumbprint_get")
    def test_063_challenge__check(self, mock_jwk, mock_chall, mock_sleep):
        """challenge check with with failed tkauth challenge tnauthlist_support not configured"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "authorization__type": "authorization__type",
            "authorization__value": "authorization__value",
            "type": "tkauth-01",
            "token": "token",
            "authorization__order__account__name": "authorization__order__account__name",
        }
        self.challenge.dbstore.jwk_load.return_value = "pub_key"
        mock_chall.side_effect = [(False, "foo")]
        mock_jwk.return_value = "jwk_thumbprint"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual((False, True), self.challenge._check("name", "payload"))
        self.assertFalse(mock_chall.called)
        self.assertIn(
            'ERROR:test_a2c:Unknown challenge type "tkauth-01". Setting check result to False',
            lcm.output,
        )

    @patch("time.sleep")
    @patch("acme_srv.challenge.Challenge._validate_tkauth_challenge")
    @patch("acme_srv.challenge.jwk_thumbprint_get")
    def test_064_challenge__check(self, mock_jwk, mock_chall, mock_sleep):
        """challenge check with with failed tkauth challenge tnauthlist_support True - for loop returns data during 1st iteration"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "authorization__type": "authorization__type",
            "authorization__value": "authorization__value",
            "type": "tkauth-01",
            "token": "token",
            "authorization__order__account__name": "authorization__order__account__name",
        }
        self.challenge.dbstore.jwk_load.return_value = "pub_key"
        self.challenge.tnauthlist_support = True
        mock_chall.side_effect = [(False, "foo")]
        mock_jwk.return_value = "jwk_thumbprint"
        self.assertEqual((False, "foo"), self.challenge._check("name", "payload"))
        self.assertTrue(mock_chall.called)

    @patch("time.sleep")
    @patch("acme_srv.challenge.Challenge._validate_tkauth_challenge")
    @patch("acme_srv.challenge.jwk_thumbprint_get")
    def test_065_challenge__check(self, mock_jwk, mock_chall, mock_sleep):
        """challenge check with with failed tkauth challenge tnauthlist_support True - for loop returns data during 2nd iteration"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "authorization__type": "authorization__type",
            "authorization__value": "authorization__value",
            "type": "tkauth-01",
            "token": "token",
            "authorization__order__account__name": "authorization__order__account__name",
        }
        self.challenge.dbstore.jwk_load.return_value = "pub_key"
        self.challenge.tnauthlist_support = True
        mock_chall.side_effect = [(False, False), (False, "foo")]
        mock_jwk.return_value = "jwk_thumbprint"
        self.assertEqual((False, "foo"), self.challenge._check("name", "payload"))
        self.assertTrue(mock_chall.called)

    @patch("time.sleep")
    @patch("acme_srv.challenge.Challenge._validate_tkauth_challenge")
    @patch("acme_srv.challenge.jwk_thumbprint_get")
    def test_066_challenge__check(self, mock_jwk, mock_chall, mock_sleep):
        """challenge check with with succ tkauth challenge and tnauthlist_support unset"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "authorization__type": "authorization__type",
            "authorization__value": "authorization__value",
            "type": "tkauth-01",
            "token": "token",
            "authorization__order__account__name": "authorization__order__account__name",
        }
        self.challenge.dbstore.jwk_load.return_value = "pub_key"
        self.challenge.tnauthlist_support = False
        mock_chall.side_effect = [(True, "foo")]
        mock_jwk.return_value = "jwk_thumbprint"
        self.assertEqual((False, True), self.challenge._check("name", "payload"))
        self.assertFalse(mock_chall.called)

    @patch("time.sleep")
    @patch("acme_srv.challenge.Challenge._validate_tkauth_challenge")
    @patch("acme_srv.challenge.jwk_thumbprint_get")
    def test_067_challenge__check(self, mock_jwk, mock_chall, mock_sleep):
        """challenge check with with succ tkauth challenge and tnauthlist support set - for loop returns data during 1st iteration"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "authorization__type": "authorization__type",
            "authorization__value": "authorization__value",
            "type": "tkauth-01",
            "token": "token",
            "authorization__order__account__name": "authorization__order__account__name",
        }
        self.challenge.dbstore.jwk_load.return_value = "pub_key"
        self.challenge.tnauthlist_support = True
        mock_chall.side_effect = [(True, "foo")]
        mock_jwk.return_value = "jwk_thumbprint"
        self.assertEqual((True, "foo"), self.challenge._check("name", "payload"))

    @patch("time.sleep")
    @patch("acme_srv.challenge.Challenge._validate_tkauth_challenge")
    @patch("acme_srv.challenge.jwk_thumbprint_get")
    def test_068_challenge__check(self, mock_jwk, mock_chall, mock_sleep):
        """challenge check with with succ tkauth challenge and tnauthlist support set - for loop returns data during 2nd iteration"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "authorization__type": "authorization__type",
            "authorization__value": "authorization__value",
            "type": "tkauth-01",
            "token": "token",
            "authorization__order__account__name": "authorization__order__account__name",
        }
        self.challenge.dbstore.jwk_load.return_value = "pub_key"
        self.challenge.tnauthlist_support = True
        mock_chall.side_effect = [(False, False), (True, "foo")]
        mock_jwk.return_value = "jwk_thumbprint"
        self.assertEqual((True, "foo"), self.challenge._check("name", "payload"))

    def test_069_challenge__wcd_manipulate(self):
        """get fqdn wc manipulation"""
        fqdn = "foo.bar"
        self.assertEqual("foo.bar", self.challenge._wcd_manipulate(fqdn))

    def test_070_challenge__wcd_manipulate(self):
        """get fqdn wc manipulation"""
        fqdn = "*.foo.bar"
        self.assertEqual("foo.bar", self.challenge._wcd_manipulate(fqdn))

    def test_071_challenge__wcd_manipulate(self):
        """get fqdn wc manipulation"""
        fqdn = "foo*.foo.bar"
        self.assertEqual("foo*.foo.bar", self.challenge._wcd_manipulate(fqdn))

    def test_072_challenge__challengelist_search(self):
        """test Challenge._challengelist_search - one challenge"""
        self.challenge.dbstore.challenges_search.return_value = [
            {"token": "token", "type": "type", "name": "name"}
        ]
        self.challenge.path_dic = {"chall_path": "/chall_path/"}
        self.challenge.server_name = "server_name"
        result = [
            {
                "name": "name",
                "token": "token",
                "type": "type",
                "url": "server_name/chall_path/name",
            }
        ]
        self.assertEqual(result, self.challenge._challengelist_search("key", "value"))

    def test_073_challenge__challengelist_search(self):
        """test Challenge._challengelist_search - two challenges"""
        self.challenge.dbstore.challenges_search.return_value = [
            {"token": "token1", "type": "type1", "name": "name1"},
            {"token": "token2", "type": "type2", "name": "name2"},
        ]
        self.challenge.path_dic = {"chall_path": "/chall_path/"}
        self.challenge.server_name = "server_name"
        result = [
            {
                "name": "name1",
                "token": "token1",
                "type": "type1",
                "url": "server_name/chall_path/name1",
            },
            {
                "name": "name2",
                "token": "token2",
                "type": "type2",
                "url": "server_name/chall_path/name2",
            },
        ]
        self.assertEqual(result, self.challenge._challengelist_search("key", "value"))

    def test_074_challenge__challengelist_search(self):
        """test Challenge._challengelist_search - one challenge with status field"""
        self.challenge.dbstore.challenges_search.return_value = [
            {"token": "token", "type": "type", "name": "name", "status__name": "status"}
        ]
        self.challenge.path_dic = {"chall_path": "/chall_path/"}
        self.challenge.server_name = "server_name"
        result = [
            {
                "name": "name",
                "token": "token",
                "type": "type",
                "url": "server_name/chall_path/name",
                "status": "status",
            }
        ]
        self.assertEqual(result, self.challenge._challengelist_search("key", "value"))

    def test_075_challenge__challengelist_search(self):
        """test Challenge._challengelist_search - two challenges with status field"""
        self.challenge.dbstore.challenges_search.return_value = [
            {
                "token": "token1",
                "type": "type1",
                "name": "name1",
                "status__name": "status",
            },
            {
                "token": "token2",
                "type": "type2",
                "name": "name2",
                "status__name": "status",
            },
        ]
        self.challenge.path_dic = {"chall_path": "/chall_path/"}
        self.challenge.server_name = "server_name"
        result = [
            {
                "name": "name1",
                "token": "token1",
                "type": "type1",
                "url": "server_name/chall_path/name1",
                "status": "status",
            },
            {
                "name": "name2",
                "token": "token2",
                "type": "type2",
                "url": "server_name/chall_path/name2",
                "status": "status",
            },
        ]
        self.assertEqual(result, self.challenge._challengelist_search("key", "value"))

    def test_076_challenge__challengelist_search(self):
        """test Challenge._challengelist_search - dbstore.challenges_search() raises an exception"""
        self.challenge.dbstore.challenges_search.side_effect = Exception(
            "exc_chall_search"
        )
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.challenge._challengelist_search("key", "value")
        self.assertIn(
            "CRITICAL:test_a2c:Database error: failed to search for challenges: exc_chall_search",
            lcm.output,
        )

    def test_077_challenge__check(self):
        """test Challenge._check - dbstore.jwk_load() raises an exception"""
        self.challenge.dbstore.jwk_load.side_effect = Exception("exc_jkw_load")
        self.challenge.dbstore.challenge_lookup.return_value = {
            "type": "type",
            "authorization__value": "authorization__value",
            "token": "token",
            "authorization__order__account__name": "authorization__order__account__name",
        }
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.challenge._check("name", "payload")
        self.assertIn(
            "CRITICAL:test_a2c:Database error: could not get jwk: exc_jkw_load",
            lcm.output,
        )

    def test_078_challenge__update_authz(self):
        """test challenge update authz"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "authorization": "authzname"
        }
        self.challenge.dbstore.authorization_update.return_value = "foo"
        self.challenge._update_authz("name", {"foo": "bar"})

    def test_079_challenge__check(self):
        """test Challenge._check - dbstore.challenge_lookup() raises an exception"""
        self.challenge.dbstore.challenge_lookup.side_effect = Exception("exc_chall_chk")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.challenge._check("name", "payload")
        self.assertIn(
            "CRITICAL:test_a2c:Database error: failed to lookup challenge during challenge check:'name': exc_chall_chk",
            lcm.output,
        )

    def test_080_challenge__info(self):
        """test Challenge._info - dbstore.challenge_lookup() raises an exception"""
        self.challenge.dbstore.challenge_lookup.side_effect = Exception(
            "exc_chall_info"
        )
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.challenge._info("name")
        self.assertIn(
            "CRITICAL:test_a2c:Database error: failed to lookup challenge: 'name': exc_chall_info",
            lcm.output,
        )

    def test_081_challenge__update(self):
        """test Challenge._update - dbstore.challenge_update() raises an exception"""
        self.challenge.dbstore.challenge_update.side_effect = Exception("exc_chall_upd")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.challenge._update({"foo": "bar"})
        self.assertIn(
            "CRITICAL:test_a2c:Database error: failed to update challenge: exc_chall_upd",
            lcm.output,
        )

    def test_082_challenge__update(self):
        """test Challenge._update - dbstore.challenge_update() raises an exception"""
        self.challenge.dbstore.challenge_update.side_effect = Exception("exc_chall_upd")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.challenge._update({"foo": "bar"})
        self.assertIn(
            "CRITICAL:test_a2c:Database error: failed to update challenge: exc_chall_upd",
            lcm.output,
        )

    def test_083_challenge__update_authz(self):
        """test Challenge._update_authz - dbstore.authorization_update() raises an exception"""
        self.challenge.dbstore.authorization_update.side_effect = Exception(
            "exc_chall_autz_upd"
        )
        self.challenge.dbstore.challenge_lookup.return_value = {
            "authorization__name": "authorization__name",
            "authorization": "authorization",
        }
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.challenge._update_authz("name", {"foo": "bar"})
        self.assertIn(
            "CRITICAL:test_a2c:Database error: failed to update authorization for challenge: exc_chall_autz_upd",
            lcm.output,
        )

    def test_084_challenge__update_authz(self):
        """test Challenge._update_authz - dbstore.authorization_update() raises an exception"""
        self.challenge.dbstore.challenge_lookup.side_effect = Exception(
            "exc_chall_lookup_foo"
        )
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.challenge._update_authz("name", {"foo": "bar"})
        self.assertIn(
            "CRITICAL:test_a2c:Database error: failed to lookup authorization for challenge 'name': exc_chall_lookup_foo",
            lcm.output,
        )

    @patch("acme_srv.challenge.fqdn_resolve")
    def test_085_challenge__validate_alpn_challenge(self, mock_resolve):
        """test validate_alpn_challenge fqdn_resolve returned Invalid"""
        mock_resolve.return_value = (None, True)
        self.assertEqual(
            (False, True),
            self.challenge._validate_alpn_challenge(
                "cert_name", "dns", "fqdn", "token", "jwk_thumbprint"
            ),
        )

    @patch("acme_srv.challenge.servercert_get")
    @patch("acme_srv.challenge.fqdn_resolve")
    def test_086_challenge__validate_alpn_challenge(self, mock_resolve, mock_srv):
        """test validate_alpn_challenge no certificate returned"""
        mock_resolve.return_value = ("foo", False)
        mock_srv.return_value = None
        self.assertEqual(
            (False, False),
            self.challenge._validate_alpn_challenge(
                "cert_name", "dns", "fqdn", "token", "jwk_thumbprint"
            ),
        )

    @patch("acme_srv.challenge.proxy_check")
    @patch("acme_srv.challenge.servercert_get")
    @patch("acme_srv.challenge.fqdn_resolve")
    def test_087_challenge__validate_alpn_challenge(
        self, mock_resolve, mock_srv, mock_proxy
    ):
        """test validate_alpn_challenge no certificate returned"""
        mock_resolve.return_value = ("foo", False)
        mock_srv.return_value = None
        self.challenge.proxy_server_list = "proxy_list"
        mock_proxy.return_value = "proxy"
        self.assertEqual(
            (False, False),
            self.challenge._validate_alpn_challenge(
                "cert_name", "dns", "fqdn", "token", "jwk_thumbprint"
            ),
        )

    @patch("acme_srv.challenge.fqdn_in_san_check")
    @patch("acme_srv.challenge.cert_san_get")
    @patch("acme_srv.challenge.servercert_get")
    @patch("acme_srv.challenge.fqdn_resolve")
    def test_088_challenge__validate_alpn_challenge(
        self, mock_resolve, mock_srv, mock_sanget, mock_sanchk
    ):
        """test validate_alpn_challenge sancheck returned false"""
        mock_resolve.return_value = ("foo", False)
        mock_sanget.return_value = ["foo", "bar"]
        mock_sanchk.return_value = False
        mock_srv.return_value = "cert"
        self.assertEqual(
            (False, False),
            self.challenge._validate_alpn_challenge(
                "cert_name", "dns", "fqdn", "token", "jwk_thumbprint"
            ),
        )

    @patch("acme_srv.challenge.cert_extensions_get")
    @patch("acme_srv.challenge.b64_encode")
    @patch("acme_srv.challenge.fqdn_in_san_check")
    @patch("acme_srv.challenge.cert_san_get")
    @patch("acme_srv.challenge.servercert_get")
    @patch("acme_srv.challenge.fqdn_resolve")
    def test_089_challenge__validate_alpn_challenge(
        self, mock_resolve, mock_srv, mock_sanget, mock_sanchk, mock_encode, mock_ext
    ):
        """test validate_alpn_challenge extension check failed"""
        mock_resolve.return_value = ("foo", False)
        mock_sanget.return_value = ["foo", "bar"]
        mock_sanchk.return_value = True
        mock_srv.return_value = "cert"
        mock_encode.return_value = "foo"
        mock_ext.return_value = ["foobar", "bar", "foo1"]
        self.assertEqual(
            (False, False),
            self.challenge._validate_alpn_challenge(
                "cert_name", "dns", "fqdn", "token", "jwk_thumbprint"
            ),
        )

    @patch("acme_srv.challenge.cert_extensions_get")
    @patch("acme_srv.challenge.b64_encode")
    @patch("acme_srv.challenge.fqdn_in_san_check")
    @patch("acme_srv.challenge.cert_san_get")
    @patch("acme_srv.challenge.servercert_get")
    @patch("acme_srv.challenge.fqdn_resolve")
    def test_090_challenge__validate_alpn_challenge(
        self, mock_resolve, mock_srv, mock_sanget, mock_sanchk, mock_encode, mock_ext
    ):
        """test validate_alpn_challenge extension sucessful"""
        mock_resolve.return_value = ("foo", False)
        mock_sanget.return_value = ["foo", "bar"]
        mock_sanchk.return_value = True
        mock_srv.return_value = "cert"
        mock_encode.return_value = "foo"
        mock_ext.return_value = ["foobar", "bar", "foo"]
        self.assertEqual(
            (True, False),
            self.challenge._validate_alpn_challenge(
                "cert_name", "dns", "fqdn", "token", "jwk_thumbprint"
            ),
        )

    @patch("acme_srv.challenge.cert_extensions_get")
    @patch("acme_srv.challenge.b64_encode")
    @patch("acme_srv.challenge.fqdn_in_san_check")
    @patch("acme_srv.challenge.cert_san_get")
    @patch("acme_srv.challenge.servercert_get")
    @patch("acme_srv.challenge.fqdn_resolve")
    def test_091_challenge__validate_alpn_challenge(
        self, mock_resolve, mock_srv, mock_sanget, mock_sanchk, mock_encode, mock_ext
    ):
        """test validate_alpn_challenge extension sucessful"""
        mock_resolve.return_value = ("foo", False)
        mock_sanget.return_value = ["foo", "bar"]
        mock_sanchk.return_value = True
        mock_srv.return_value = "cert"
        mock_encode.return_value = "foo"
        mock_ext.return_value = ["foobar", "bar", "foo"]
        self.assertEqual(
            (True, False),
            self.challenge._validate_alpn_challenge(
                "cert_name", "ip", "192.168.0.1", "token", "jwk_thumbprint"
            ),
        )
        self.assertFalse(mock_resolve.called)

    @patch("acme_srv.challenge.cert_extensions_get")
    @patch("acme_srv.challenge.b64_encode")
    @patch("acme_srv.challenge.fqdn_in_san_check")
    @patch("acme_srv.challenge.cert_san_get")
    @patch("acme_srv.challenge.servercert_get")
    @patch("acme_srv.challenge.fqdn_resolve")
    def test_092_challenge__validate_alpn_challenge(
        self, mock_resolve, mock_srv, mock_sanget, mock_sanchk, mock_encode, mock_ext
    ):
        """test validate_alpn_challenge up with unknown value"""
        mock_resolve.return_value = ("foo", False)
        mock_sanget.return_value = ["foo", "bar"]
        mock_sanchk.return_value = True
        mock_srv.return_value = "cert"
        mock_encode.return_value = "foo"
        mock_ext.return_value = ["foobar", "bar", "foo"]
        self.assertEqual(
            (False, True),
            self.challenge._validate_alpn_challenge(
                "cert_name", "ip", "somethingwrong", "token", "jwk_thumbprint"
            ),
        )
        self.assertFalse(mock_resolve.called)

    @patch("acme_srv.challenge.cert_extensions_get")
    @patch("acme_srv.challenge.b64_encode")
    @patch("acme_srv.challenge.fqdn_in_san_check")
    @patch("acme_srv.challenge.cert_san_get")
    @patch("acme_srv.challenge.servercert_get")
    @patch("acme_srv.challenge.fqdn_resolve")
    def test_093_challenge__validate_alpn_challenge(
        self, mock_resolve, mock_srv, mock_sanget, mock_sanchk, mock_encode, mock_ext
    ):
        """test validate_alpn_challenge ipv6 extension sucessful"""
        mock_resolve.return_value = ("foo", False)
        mock_sanget.return_value = ["foo", "bar"]
        mock_sanchk.return_value = True
        mock_srv.return_value = "cert"
        mock_encode.return_value = "foo"
        mock_ext.return_value = ["foobar", "bar", "foo"]
        self.assertEqual(
            (True, False),
            self.challenge._validate_alpn_challenge(
                "cert_name", "ip", "fe80::215:5dff:fec0:102", "token", "jwk_thumbprint"
            ),
        )
        self.assertFalse(mock_resolve.called)

    @patch("acme_srv.challenge.cert_extensions_get")
    @patch("acme_srv.challenge.b64_encode")
    @patch("acme_srv.challenge.fqdn_in_san_check")
    @patch("acme_srv.challenge.cert_san_get")
    @patch("acme_srv.challenge.servercert_get")
    @patch("acme_srv.challenge.fqdn_resolve")
    def test_094_challenge__validate_alpn_challenge(
        self, mock_resolve, mock_srv, mock_sanget, mock_sanchk, mock_encode, mock_ext
    ):
        """test validate_alpn_challenge extension sucessful"""
        mock_encode.return_value = "foo"
        self.assertEqual(
            (False, True),
            self.challenge._validate_alpn_challenge(
                "cert_name", "unk", "fqdn", "token", "jwk_thumbprint"
            ),
        )
        self.assertFalse(mock_resolve.called)
        self.assertFalse(mock_srv.called)
        self.assertFalse(mock_sanget.called)
        self.assertFalse(mock_sanchk.called)
        self.assertTrue(mock_encode.called)
        self.assertFalse(mock_ext.called)

    @patch("acme_srv.challenge.Challenge._validate")
    def test_095__existing_challenge_validate(self, mock_validate):
        """validate challenge with empty challenge list"""
        challenge_list = []
        self.challenge._existing_challenge_validate(challenge_list)
        self.assertFalse(mock_validate.called)

    @patch("acme_srv.challenge.Challenge._validate")
    def test_096__existing_challenge_validate(self, mock_validate):
        """validate challenge with challenge list"""
        challenge_list = [{"name": "foo", "type": "http-01"}]
        self.challenge._existing_challenge_validate(challenge_list)
        self.assertTrue(mock_validate.called)

    @patch("acme_srv.challenge.load_config")
    def test_097_config_load(self, mock_load_cfg):
        """test _config_load empty config"""
        parser = configparser.ConfigParser()
        # parser['Account'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.dns_server_list)
        self.assertFalse(self.challenge.sectigo_sim)
        self.assertEqual(10, self.challenge.challenge_validation_timeout)
        self.assertEqual(0.5, self.challenge.dns_validation_pause_timer)
        self.assertFalse(self.challenge.forward_address_check)
        self.assertFalse(self.challenge.reverse_address_check)

    @patch("acme_srv.challenge.load_config")
    def test_098_config_load(self, mock_load_cfg):
        """test _config_load challenge_validation_disable False"""
        parser = configparser.ConfigParser()
        parser["Challenge"] = {"challenge_validation_disable": False}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.dns_server_list)
        self.assertFalse(self.challenge.sectigo_sim)
        self.assertEqual(10, self.challenge.challenge_validation_timeout)
        self.assertEqual(0.5, self.challenge.dns_validation_pause_timer)
        self.assertFalse(self.challenge.forward_address_check)
        self.assertFalse(self.challenge.reverse_address_check)

    @patch("acme_srv.challenge.load_config")
    def test_099_config_load(self, mock_load_cfg):
        """test _config_load challenge_validation_disable True"""
        parser = configparser.ConfigParser()
        parser["Challenge"] = {"challenge_validation_disable": True}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertTrue(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.dns_server_list)
        self.assertFalse(self.challenge.sectigo_sim)
        self.assertEqual(10, self.challenge.challenge_validation_timeout)
        self.assertEqual(0.5, self.challenge.dns_validation_pause_timer)
        self.assertFalse(self.challenge.forward_address_check)
        self.assertFalse(self.challenge.reverse_address_check)

    @patch("acme_srv.challenge.load_config")
    def test_100_config_load(self, mock_load_cfg):
        """test _config_load tnauthlist_support False"""
        parser = configparser.ConfigParser()
        parser["Order"] = {"tnauthlist_support": False}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.dns_server_list)
        self.assertFalse(self.challenge.sectigo_sim)
        self.assertEqual(10, self.challenge.challenge_validation_timeout)
        self.assertEqual(0.5, self.challenge.dns_validation_pause_timer)
        self.assertFalse(self.challenge.forward_address_check)
        self.assertFalse(self.challenge.reverse_address_check)

    @patch("acme_srv.challenge.load_config")
    def test_101_config_load(self, mock_load_cfg):
        """test _config_load tnauthlist_support True"""
        parser = configparser.ConfigParser()
        parser["Order"] = {"tnauthlist_support": True}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertTrue(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.dns_server_list)
        self.assertFalse(self.challenge.sectigo_sim)
        self.assertEqual(10, self.challenge.challenge_validation_timeout)
        self.assertEqual(0.5, self.challenge.dns_validation_pause_timer)
        self.assertFalse(self.challenge.forward_address_check)
        self.assertFalse(self.challenge.reverse_address_check)

    @patch("acme_srv.challenge.load_config")
    def test_102_config_load(self, mock_load_cfg):
        """test _config_load one DNS"""
        parser = configparser.ConfigParser()
        parser["Challenge"] = {"dns_server_list": '["10.10.10.10"]'}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertEqual(["10.10.10.10"], self.challenge.dns_server_list)
        self.assertFalse(self.challenge.sectigo_sim)
        self.assertEqual(10, self.challenge.challenge_validation_timeout)
        self.assertEqual(0.5, self.challenge.dns_validation_pause_timer)
        self.assertFalse(self.challenge.forward_address_check)
        self.assertFalse(self.challenge.reverse_address_check)

    @patch("acme_srv.challenge.load_config")
    def test_103_config_load(self, mock_load_cfg):
        """test _config_load two DNS"""
        parser = configparser.ConfigParser()
        parser["Challenge"] = {"dns_server_list": '["10.10.10.10", "10.0.0.1"]'}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertEqual(["10.10.10.10", "10.0.0.1"], self.challenge.dns_server_list)
        self.assertFalse(self.challenge.sectigo_sim)
        self.assertEqual(10, self.challenge.challenge_validation_timeout)
        self.assertEqual(0.5, self.challenge.dns_validation_pause_timer)
        self.assertFalse(self.challenge.forward_address_check)
        self.assertFalse(self.challenge.reverse_address_check)

    @patch("json.loads")
    @patch("acme_srv.challenge.load_config")
    def test_104_config_load(self, mock_load_cfg, mock_json):
        """test _config_load two DNS"""
        parser = configparser.ConfigParser()
        parser["Challenge"] = {"dns_server_list": '["10.10.10.10", "10.0.0.1"]'}
        mock_load_cfg.return_value = parser
        mock_json.side_effect = Exception("exc_mock_json")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.challenge._config_load()
        self.assertIn(
            "WARNING:test_a2c:Failed to load dns_server_list from configuration: exc_mock_json",
            lcm.output,
        )
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.dns_server_list)
        self.assertFalse(self.challenge.sectigo_sim)
        self.assertEqual(10, self.challenge.challenge_validation_timeout)
        self.assertEqual(0.5, self.challenge.dns_validation_pause_timer)
        self.assertFalse(self.challenge.forward_address_check)
        self.assertFalse(self.challenge.reverse_address_check)

    @patch("acme_srv.challenge.load_config")
    def test_105_config_load(self, mock_load_cfg):
        """test _config_load tnauthlist_support False"""
        parser = configparser.ConfigParser()
        parser["Directory"] = {"url_prefix": "url_prefix/"}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.dns_server_list)
        self.assertEqual(
            {
                "authz_path": "url_prefix//acme/authz/",
                "chall_path": "url_prefix//acme/chall/",
            },
            self.challenge.path_dic,
        )
        self.assertFalse(self.challenge.sectigo_sim)
        self.assertEqual(10, self.challenge.challenge_validation_timeout)
        self.assertEqual(0.5, self.challenge.dns_validation_pause_timer)
        self.assertFalse(self.challenge.forward_address_check)
        self.assertFalse(self.challenge.reverse_address_check)

    @patch("acme_srv.challenge.load_config")
    def test_106_config_load(self, mock_load_cfg):
        """test _config_load one DNS"""
        parser = configparser.ConfigParser()
        parser["DEFAULT"] = {
            "proxy_server_list": '{"key1.bar.local": "val1.bar.local"}'
        }
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertEqual(
            {"key1.bar.local": "val1.bar.local"}, self.challenge.proxy_server_list
        )
        self.assertFalse(self.challenge.sectigo_sim)
        self.assertEqual(10, self.challenge.challenge_validation_timeout)
        self.assertEqual(0.5, self.challenge.dns_validation_pause_timer)
        self.assertFalse(self.challenge.forward_address_check)
        self.assertFalse(self.challenge.reverse_address_check)

    @patch("acme_srv.challenge.load_config")
    def test_107_config_load(self, mock_load_cfg):
        """test _config_load one DNS"""
        parser = configparser.ConfigParser()
        parser["DEFAULT"] = {
            "proxy_server_list": '{"key1.bar.local": "val1.bar.local", "key2.bar.local": "val2.bar.local"}'
        }
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertEqual(
            {"key1.bar.local": "val1.bar.local", "key2.bar.local": "val2.bar.local"},
            self.challenge.proxy_server_list,
        )
        self.assertFalse(self.challenge.sectigo_sim)
        self.assertEqual(10, self.challenge.challenge_validation_timeout)
        self.assertEqual(0.5, self.challenge.dns_validation_pause_timer)
        self.assertFalse(self.challenge.forward_address_check)
        self.assertFalse(self.challenge.reverse_address_check)

    @patch("json.loads")
    @patch("acme_srv.challenge.load_config")
    def test_108_config_load(self, mock_load_cfg, mock_json):
        """test _config_load exception"""
        parser = configparser.ConfigParser()
        parser["DEFAULT"] = {
            "proxy_server_list": '{"key1.bar.local": "val1.bar.local"}'
        }
        mock_load_cfg.return_value = parser
        mock_json.side_effect = Exception("exc_mock_json")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.challenge._config_load()
        self.assertIn(
            "WARNING:test_a2c:Failed to load proxy_server_list from configuration: exc_mock_json",
            lcm.output,
        )
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.proxy_server_list)
        self.assertFalse(self.challenge.sectigo_sim)
        self.assertEqual(10, self.challenge.challenge_validation_timeout)
        self.assertEqual(0.5, self.challenge.dns_validation_pause_timer)
        self.assertFalse(self.challenge.forward_address_check)
        self.assertFalse(self.challenge.reverse_address_check)

    @patch("acme_srv.challenge.load_config")
    def test_109_config_load(self, mock_load_cfg):
        """test _config_load one DNS"""
        parser = configparser.ConfigParser()
        parser["Challenge"] = {"challenge_validation_timeout": 5}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.proxy_server_list)
        self.assertFalse(self.challenge.sectigo_sim)
        self.assertEqual(5, self.challenge.challenge_validation_timeout)
        self.assertEqual(0.5, self.challenge.dns_validation_pause_timer)
        self.assertFalse(self.challenge.forward_address_check)
        self.assertFalse(self.challenge.reverse_address_check)

    @patch("acme_srv.challenge.load_config")
    def test_110_config_load(self, mock_load_cfg):
        """test _config_load exception"""
        parser = configparser.ConfigParser()
        parser["Challenge"] = {"challenge_validation_timeout": "AA"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.challenge._config_load()
        self.assertIn(
            "WARNING:test_a2c:Failed to parse challenge_validation_timeout from configuration: invalid literal for int() with base 10: 'AA'",
            lcm.output,
        )
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.proxy_server_list)
        self.assertFalse(self.challenge.sectigo_sim)
        self.assertEqual(10, self.challenge.challenge_validation_timeout)
        self.assertEqual(0.5, self.challenge.dns_validation_pause_timer)
        self.assertFalse(self.challenge.forward_address_check)
        self.assertFalse(self.challenge.reverse_address_check)

    @patch("acme_srv.challenge.load_config")
    def test_111_config_load(self, mock_load_cfg):
        """test _config_load sectigo_sim"""
        parser = configparser.ConfigParser()
        parser["Challenge"] = {"sectigo_sim": True}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.proxy_server_list)
        self.assertTrue(self.challenge.sectigo_sim)
        self.assertEqual(10, self.challenge.challenge_validation_timeout)
        self.assertEqual(0.5, self.challenge.dns_validation_pause_timer)
        self.assertFalse(self.challenge.forward_address_check)
        self.assertFalse(self.challenge.reverse_address_check)

    @patch("acme_srv.challenge.load_config")
    def test_112_config_load(self, mock_load_cfg):
        """test _config_load sectigo_sim"""
        parser = configparser.ConfigParser()
        parser["Challenge"] = {"sectigo_sim": False}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.proxy_server_list)
        self.assertFalse(self.challenge.sectigo_sim)
        self.assertEqual(10, self.challenge.challenge_validation_timeout)
        self.assertEqual(0.5, self.challenge.dns_validation_pause_timer)
        self.assertFalse(self.challenge.forward_address_check)
        self.assertFalse(self.challenge.reverse_address_check)

    @patch("acme_srv.challenge.load_config")
    def test_113_config_load(self, mock_load_cfg):
        """test _config_load sectigo_sim"""
        parser = configparser.ConfigParser()
        parser["Challenge"] = {"dns_validation_pause_timer": 20}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.proxy_server_list)
        self.assertFalse(self.challenge.sectigo_sim)
        self.assertEqual(10, self.challenge.challenge_validation_timeout)
        self.assertEqual(20, self.challenge.dns_validation_pause_timer)
        self.assertFalse(self.challenge.forward_address_check)
        self.assertFalse(self.challenge.reverse_address_check)

    @patch("acme_srv.challenge.load_config")
    def test_114_config_load(self, mock_load_cfg):
        """test _config_load sectigo_sim"""
        parser = configparser.ConfigParser()
        parser["Challenge"] = {"dns_validation_pause_timer": "aa"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.challenge._config_load()
        self.assertIn(
            "WARNING:test_a2c:Failed to parse dns_validation_pause_timer from configuration: invalid literal for int() with base 10: 'aa'",
            lcm.output,
        )
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.proxy_server_list)
        self.assertFalse(self.challenge.sectigo_sim)
        self.assertEqual(10, self.challenge.challenge_validation_timeout)
        self.assertEqual(0.5, self.challenge.dns_validation_pause_timer)
        self.assertFalse(self.challenge.forward_address_check)
        self.assertFalse(self.challenge.reverse_address_check)

    @patch("acme_srv.challenge.load_config")
    def test_115_config_load(self, mock_load_cfg):
        """test _config_load sectigo_sim"""
        parser = configparser.ConfigParser()
        parser["Challenge"] = {"forward_address_check": True}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.proxy_server_list)
        self.assertFalse(self.challenge.sectigo_sim)
        self.assertEqual(10, self.challenge.challenge_validation_timeout)
        self.assertEqual(0.5, self.challenge.dns_validation_pause_timer)
        self.assertTrue(self.challenge.forward_address_check)
        self.assertFalse(self.challenge.reverse_address_check)

    @patch("acme_srv.challenge.load_config")
    def test_215_config_load(self, mock_load_cfg):
        """test _config_load sectigo_sim"""
        parser = configparser.ConfigParser()
        parser["Challenge"] = {"source_address_check": True}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.challenge._config_load()
        self.assertIn(
            "WARNING:test_a2c:source_address_check is deprecated, please use forward_address_check instead",
            lcm.output,
        )
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.proxy_server_list)
        self.assertFalse(self.challenge.sectigo_sim)
        self.assertEqual(10, self.challenge.challenge_validation_timeout)
        self.assertEqual(0.5, self.challenge.dns_validation_pause_timer)
        self.assertTrue(self.challenge.forward_address_check)
        self.assertFalse(self.challenge.reverse_address_check)

    @patch("acme_srv.challenge.load_config")
    def test_216_config_load(self, mock_load_cfg):
        """test _config_load sectigo_sim"""
        parser = configparser.ConfigParser()
        parser["Challenge"] = {"reverse_address_check": True}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.proxy_server_list)
        self.assertFalse(self.challenge.sectigo_sim)
        self.assertEqual(10, self.challenge.challenge_validation_timeout)
        self.assertEqual(0.5, self.challenge.dns_validation_pause_timer)
        self.assertFalse(self.challenge.forward_address_check)
        self.assertTrue(self.challenge.reverse_address_check)

    @patch("acme_srv.challenge.load_config")
    def test_116_config_load(self, mock_load_cfg):
        """test _config_load sectigo_sim"""
        parser = configparser.ConfigParser()
        parser["Challenge"] = {"forward_address_check": False}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.proxy_server_list)
        self.assertFalse(self.challenge.sectigo_sim)
        self.assertEqual(10, self.challenge.challenge_validation_timeout)
        self.assertEqual(0.5, self.challenge.dns_validation_pause_timer)
        self.assertFalse(self.challenge.forward_address_check)
        self.assertFalse(self.challenge.reverse_address_check)

    @patch("acme_srv.challenge.load_config")
    def test_117_config_load(self, mock_load_cfg):
        """test _config_load sectigo_sim"""
        parser = configparser.ConfigParser()
        parser["DEFAULT"] = {"email_address": "email@email.com"}
        parser["Order"] = {"email_identifier_support": True}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.proxy_server_list)
        self.assertFalse(self.challenge.sectigo_sim)
        self.assertEqual(10, self.challenge.challenge_validation_timeout)
        self.assertEqual(0.5, self.challenge.dns_validation_pause_timer)
        self.assertFalse(self.challenge.forward_address_check)
        self.assertTrue(self.challenge.email_identifier_support)
        self.assertEqual("email@email.com", self.challenge.email_address)
        self.assertFalse(self.challenge.reverse_address_check)

    @patch("acme_srv.challenge.load_config")
    def test_118_config_load(self, mock_load_cfg):
        """test _config_load sectigo_sim"""
        parser = configparser.ConfigParser()
        parser["DEFAULT"] = {"email_address": "email@email.com"}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.proxy_server_list)
        self.assertFalse(self.challenge.sectigo_sim)
        self.assertEqual(10, self.challenge.challenge_validation_timeout)
        self.assertEqual(0.5, self.challenge.dns_validation_pause_timer)
        self.assertFalse(self.challenge.forward_address_check)
        self.assertFalse(self.challenge.email_identifier_support)
        self.assertFalse(self.challenge.email_address)
        self.assertFalse(self.challenge.reverse_address_check)

    def test_119__name_get(self):
        """test name get no touch"""
        url = "foo"
        self.assertEqual("foo", self.challenge._name_get(url))

    @patch("acme_srv.challenge.parse_url")
    def test_120__name_get(self, mock_parse):
        """test name get urlparse"""
        mock_parse.return_value = {"path": "path"}
        url = "foo"
        self.assertEqual("path", self.challenge._name_get(url))

    @patch("acme_srv.challenge.parse_url")
    def test_121__name_get(self, mock_parse):
        """test name get challenge_path replace"""
        mock_parse.return_value = {"path": "foo/my_path"}
        self.challenge.path_dic = {"chall_path": "foo/"}
        url = "foo"
        self.assertEqual("my_path", self.challenge._name_get(url))

    @patch("acme_srv.challenge.parse_url")
    def test_122__name_get(self, mock_parse):
        """test name get challenge_path replace"""
        mock_parse.return_value = {"path": "foo/my/path"}
        self.challenge.path_dic = {"chall_path": "foo/"}
        url = "foo"
        self.assertEqual("my", self.challenge._name_get(url))

    @patch("acme_srv.challenge.Challenge._update_authz")
    @patch("acme_srv.challenge.Challenge._update")
    def test_123__validate(self, mock_update, mock_aupdate):
        """test validate"""
        challenge_name = "challenge_name"
        payload = "payload"
        mock_update.return_value = True
        mock_aupdate.return_value = True
        self.challenge.challenge_validation_disable = True
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertTrue(self.challenge._validate(challenge_name, payload))
        self.assertIn(
            "WARNING:test_a2c:Challenge validation is globally disabled. Setting challenge status to valid.",
            lcm.output,
        )
        self.assertTrue(mock_update.called)
        self.assertTrue(mock_aupdate.called)

    @patch("acme_srv.challenge.Challenge._forward_address_check")
    @patch("acme_srv.challenge.Challenge._update_authz")
    @patch("acme_srv.challenge.Challenge._update")
    def test_124__validate(self, mock_update, mock_aupdate, mock_srcchk):
        """test validate"""
        challenge_name = "challenge_name"
        payload = "payload"
        mock_update.return_value = True
        mock_aupdate.return_value = True
        self.challenge.challenge_validation_disable = True
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertTrue(self.challenge._validate(challenge_name, payload))
        self.assertIn(
            "WARNING:test_a2c:Challenge validation is globally disabled. Setting challenge status to valid.",
            lcm.output,
        )
        self.assertTrue(mock_update.called)
        self.assertTrue(mock_aupdate.called)
        self.assertFalse(mock_srcchk.called)

    @patch("acme_srv.challenge.Challenge._forward_address_check")
    @patch("acme_srv.challenge.Challenge._update_authz")
    @patch("acme_srv.challenge.Challenge._update")
    def test_125__validate(self, mock_update, mock_aupdate, mock_srcchk):
        """test validate"""
        challenge_name = "challenge_name"
        payload = "payload"
        mock_update.return_value = True
        mock_aupdate.return_value = True
        mock_srcchk.return_value = ["foo1", "foo2"]
        self.challenge.challenge_validation_disable = True
        self.challenge.forward_address_check = True
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual("foo1", self.challenge._validate(challenge_name, payload))
        self.assertIn(
            "WARNING:test_a2c:Challenge validation is globally disabled. Setting challenge status to valid.",
            lcm.output,
        )
        self.assertTrue(mock_update.called)
        self.assertTrue(mock_aupdate.called)
        self.assertTrue(mock_srcchk.called)

    @patch("acme_srv.challenge.Challenge._cvd_via_eabprofile_check")
    @patch("acme_srv.challenge.Challenge._update_authz")
    @patch("acme_srv.challenge.Challenge._update")
    def test_126__validate(self, mock_update, mock_aupdate, mock_cvd_check):
        """test validate"""
        challenge_name = "challenge_name"
        payload = "payload"
        mock_update.return_value = True
        mock_aupdate.return_value = True
        mock_cvd_check.return_value = True
        self.challenge.challenge_validation_disable = False
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertTrue(self.challenge._validate(challenge_name, payload))
        self.assertIn(
            "INFO:test_a2c:Challenge validation disabled via eab profile. Setting challenge status to valid.",
            lcm.output,
        )
        self.assertTrue(mock_update.called)
        self.assertTrue(mock_aupdate.called)

    @patch("acme_srv.challenge.Challenge._cvd_via_eabprofile_check")
    @patch("acme_srv.challenge.Challenge._update_authz")
    @patch("acme_srv.challenge.Challenge._update")
    def test_127__validate(self, mock_update, mock_aupdate, mock_cvd_check):
        """test validate"""
        challenge_name = "challenge_name"
        payload = "payload"
        mock_update.return_value = True
        mock_aupdate.return_value = True
        mock_cvd_check.return_value = False
        self.challenge.challenge_validation_disable = True
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertTrue(self.challenge._validate(challenge_name, payload))
        self.assertIn(
            "WARNING:test_a2c:Challenge validation is globally disabled. Setting challenge status to valid.",
            lcm.output,
        )
        self.assertTrue(mock_update.called)
        self.assertTrue(mock_aupdate.called)

    @patch("acme_srv.challenge.Challenge._cvd_via_eabprofile_check")
    @patch("acme_srv.challenge.Challenge._update_authz")
    @patch("acme_srv.challenge.Challenge._update")
    def test_128__validate(self, mock_update, mock_aupdate, mock_cvd_check):
        """test validate"""
        challenge_name = "challenge_name"
        payload = "payload"
        mock_update.return_value = True
        mock_aupdate.return_value = True
        mock_cvd_check.return_value = False
        self.challenge.challenge_validation_disable = False
        self.assertFalse(self.challenge._validate(challenge_name, payload))
        self.assertTrue(mock_update.called)
        self.assertFalse(mock_aupdate.called)

    @patch("acme_srv.challenge.Challenge._cvd_via_eabprofile_check")
    @patch("acme_srv.challenge.Challenge._update_authz")
    @patch("acme_srv.challenge.Challenge._update")
    def test_129__validate(self, mock_update, mock_aupdate, mock_cvd_check):
        """test validate"""
        challenge_name = "challenge_name"
        payload = "payload"
        mock_update.return_value = True
        mock_aupdate.return_value = True
        mock_cvd_check.return_value = True
        self.challenge.challenge_validation_disable = True
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertTrue(self.challenge._validate(challenge_name, payload))
        self.assertIn(
            "WARNING:test_a2c:Challenge validation is globally disabled. Setting challenge status to valid.",
            lcm.output,
        )
        self.assertTrue(mock_update.called)
        self.assertTrue(mock_aupdate.called)

    @patch("acme_srv.challenge.Challenge._check")
    @patch("acme_srv.challenge.Challenge._update_authz")
    @patch("acme_srv.challenge.Challenge._update")
    def test_130__validate(self, mock_update, mock_aupdate, mock_check):
        """test validate check returned ch:False/inv:False"""
        challenge_name = "challenge_name"
        payload = "payload"
        mock_update.return_value = True
        mock_aupdate.return_value = True
        mock_check.return_value = (False, False)
        self.assertFalse(self.challenge._validate(challenge_name, payload))
        self.assertTrue(mock_update.called)
        self.assertFalse(mock_aupdate.called)

    @patch("acme_srv.challenge.Challenge._check")
    @patch("acme_srv.challenge.Challenge._update_authz")
    @patch("acme_srv.challenge.Challenge._update")
    def test_131__validate(self, mock_update, mock_aupdate, mock_check):
        """test validate check returned ch:False/inv:True"""
        challenge_name = "challenge_name"
        payload = "payload"
        mock_update.return_value = True
        mock_aupdate.return_value = True
        mock_check.return_value = (False, True)
        self.assertFalse(self.challenge._validate(challenge_name, payload))
        self.assertTrue(mock_update.called)
        self.assertTrue(mock_aupdate.called)

    @patch("acme_srv.challenge.Challenge._check")
    @patch("acme_srv.challenge.Challenge._update_authz")
    @patch("acme_srv.challenge.Challenge._update")
    def test_132__validate(self, mock_update, mock_aupdate, mock_check):
        """test validate check returned ch:True/inv:False"""
        challenge_name = "challenge_name"
        payload = "payload"
        mock_update.return_value = True
        mock_aupdate.return_value = True
        mock_check.return_value = (True, False)
        self.assertTrue(self.challenge._validate(challenge_name, payload))
        self.assertTrue(mock_update.called)
        self.assertTrue(mock_aupdate.called)

    @patch("acme_srv.challenge.Challenge._check")
    @patch("acme_srv.challenge.Challenge._update_authz")
    @patch("acme_srv.challenge.Challenge._update")
    def test_133__validate(self, mock_update, mock_aupdate, mock_check):
        """test validate check returned ch:True/inv:True"""
        challenge_name = "challenge_name"
        payload = "payload"
        mock_update.return_value = True
        mock_aupdate.return_value = True
        mock_check.return_value = (True, True)
        self.assertTrue(self.challenge._validate(challenge_name, payload))
        self.assertTrue(mock_update.called)
        self.assertTrue(mock_aupdate.called)

    @patch("acme_srv.challenge.Challenge._check")
    @patch("acme_srv.challenge.Challenge._update_authz")
    @patch("acme_srv.challenge.Challenge._update")
    def test_134__validate(self, mock_update, mock_aupdate, mock_check):
        """test validate check returned ch:True/inv:False"""
        challenge_name = "challenge_name"
        payload = {"keyAuthorization": "keyAuthorization"}
        mock_update.return_value = True
        mock_aupdate.return_value = True
        mock_check.return_value = (True, False)
        self.assertTrue(self.challenge._validate(challenge_name, payload))
        self.assertTrue(mock_update.called)
        self.assertTrue(mock_aupdate.called)

    @patch("acme_srv.challenge.Challenge._name_get")
    @patch("acme_srv.challenge.Challenge._info")
    def test_135_get(self, mock_info, mock_name):
        """test get"""
        mock_info.return_value = "chall_info"
        mock_name.return_value = "foo"
        self.assertEqual({"code": 200, "data": "chall_info"}, self.challenge.get("url"))
        self.assertTrue(mock_name.called)

    @patch("acme_srv.challenge.Challenge.new_set")
    @patch("acme_srv.challenge.Challenge._existing_challenge_validate")
    @patch("acme_srv.challenge.Challenge._challengelist_search")
    def test_136_challengeset_get(self, mock_chsearch, mock_val, mock_set):
        """test challengeset_get - no challenge_list returned"""
        mock_chsearch.return_value = []
        mock_val.return_value = True
        mock_set.return_value = "new_set"
        self.assertEqual(
            "new_set",
            self.challenge.challengeset_get(
                "authz_name", "auth_status", "token", "tnauth"
            ),
        )
        self.assertTrue(mock_set.called)
        self.assertFalse(mock_val.called)

    @patch("acme_srv.challenge.Challenge.new_set")
    @patch("acme_srv.challenge.Challenge._existing_challenge_validate")
    @patch("acme_srv.challenge.Challenge._challengelist_search")
    def test_137_challengeset_get(self, mock_chsearch, mock_val, mock_set):
        """test challengeset_get - challenge_list returned"""
        mock_chsearch.return_value = [{"name": "name1", "foo": "bar"}]
        mock_val.return_value = True
        mock_set.return_value = "new_set"
        self.assertEqual(
            [{"foo": "bar"}],
            self.challenge.challengeset_get(
                "authz_name", "auth_status", "token", "tnauth"
            ),
        )
        self.assertFalse(mock_set.called)
        self.assertFalse(mock_val.called)

    @patch("acme_srv.challenge.Challenge.new_set")
    @patch("acme_srv.challenge.Challenge._existing_challenge_validate")
    @patch("acme_srv.challenge.Challenge._challengelist_search")
    def test_138_challengeset_get(self, mock_chsearch, mock_val, mock_set):
        """test challengeset_get - challenge_list returned"""
        mock_chsearch.return_value = [{"name": "name1", "type": "email-reply-00"}]
        mock_val.return_value = True
        mock_set.return_value = "new_set"
        self.challenge.email_identifier_support = True
        self.challenge.email_address = "foo@bar.local"
        self.assertEqual(
            [{"from": "foo@bar.local", "type": "email-reply-00"}],
            self.challenge.challengeset_get(
                "authz_name", "auth_status", "token", "tnauth"
            ),
        )
        self.assertFalse(mock_set.called)
        self.assertFalse(mock_val.called)

    @patch("acme_srv.challenge.Challenge.new_set")
    @patch("acme_srv.challenge.Challenge._existing_challenge_validate")
    @patch("acme_srv.challenge.Challenge._challengelist_search")
    def test_139_challengeset_get(self, mock_chsearch, mock_val, mock_set):
        """test challengeset_get - challenge_list returned"""
        mock_chsearch.return_value = [{"name": "name1", "type": "foo"}]
        mock_val.return_value = True
        mock_set.return_value = "new_set"
        self.challenge.email_identifier_support = True
        self.challenge.email_address = "foo@bar.local"
        self.assertEqual(
            [{"type": "foo"}],
            self.challenge.challengeset_get(
                "authz_name", "auth_status", "token", "tnauth"
            ),
        )
        self.assertFalse(mock_set.called)
        self.assertFalse(mock_val.called)

    def test_140_cvd_via_eabprofile_check(self):
        """test _cvd_via_eabprofile_check with profiling disabled"""
        self.challenge.eab_profiling = False
        self.challenge.eab_handler = None
        self.challenge.dbstore.challenge_lookup.return_value = {"foo": "bar"}
        self.assertFalse(self.challenge._cvd_via_eabprofile_check("challenge_name"))

    def test_141_cvd_via_eabprofile_check(self):
        """test _cvd_via_eabprofile_check with no handler"""
        self.challenge.eab_profiling = True
        self.challenge.eab_handler = None
        self.challenge.dbstore.challenge_lookup.return_value = {"foo": "bar"}
        self.assertFalse(self.challenge._cvd_via_eabprofile_check("challenge_name"))

    def test_142_cvd_via_eabprofile_check(self):
        """test _cvd_via_eabprofile_check with handler but profiling disabled"""
        self.challenge.eab_profiling = False
        self.challenge.eab_handler = MagicMock()
        self.challenge.dbstore.challenge_lookup.return_value = {"foo": "bar"}
        self.assertFalse(self.challenge._cvd_via_eabprofile_check("challenge_name"))

    def test_143_cvd_via_eabprofile_check(self):
        """test _cvd_via_eabprofile_check enabled but no useful data returned"""
        self.challenge.eab_profiling = True
        self.challenge.eab_handler = MagicMock()
        self.challenge.dbstore.challenge_lookup.return_value = {"foo": "bar"}
        self.challenge.dbstore.challenge_lookup.side_effect = None
        self.assertFalse(self.challenge._cvd_via_eabprofile_check("challenge_name"))

    def test_144_cvd_via_eabprofile_check(self):
        """test _cvd_via_eabprofile_check enabled but exception during db lookup"""
        self.challenge.eab_profiling = True
        self.challenge.eab_handler = MagicMock()
        self.challenge.dbstore.challenge_lookup.side_effect = Exception(
            "exc_chall_info"
        )
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(self.challenge._cvd_via_eabprofile_check("challenge_name"))
        self.assertIn(
            "CRITICAL:test_a2c:Database error: failed to lookup challenge during profile check:'challenge_name': exc_chall_info",
            lcm.output,
        )

    def test_145_cvd_via_eabprofile_check(self):
        """test _cvd_via_eabprofile_check enabled cvd True"""
        self.challenge.eab_profiling = True
        self.challenge.eab_handler = MagicMock()
        self.challenge.eab_handler.return_value.__enter__.return_value.key_file_load.return_value = {
            "eab_kid": {
                "foo": "bar",
                "challenge": {"challenge_validation_disable": True},
            }
        }
        self.challenge.dbstore.challenge_lookup.return_value = {
            "foo": "bar",
            "authorization__order__account__eab_kid": "eab_kid",
        }
        self.challenge.dbstore.challenge_lookup.side_effect = None
        self.assertTrue(self.challenge._cvd_via_eabprofile_check("challenge_name"))

    def test_146_cvd_via_eabprofile_check(self):
        """test _cvd_via_eabprofile_check enabled cvd False"""
        self.challenge.eab_profiling = True
        self.challenge.eab_handler = MagicMock()
        self.challenge.eab_handler.return_value.__enter__.return_value.key_file_load.return_value = {
            "eab_kid": {
                "foo": "bar",
                "challenge": {"challenge_validation_disable": False},
            }
        }
        self.challenge.dbstore.challenge_lookup.return_value = {
            "foo": "bar",
            "authorization__order__account__eab_kid": "eab_kid",
        }
        self.challenge.dbstore.challenge_lookup.side_effect = None
        self.assertFalse(self.challenge._cvd_via_eabprofile_check("challenge_name"))

    def test_147_cvd_via_eabprofile_check(self):
        """test _cvd_via_eabprofile_check enabled cvd True"""
        self.challenge.eab_profiling = True
        self.challenge.eab_handler = MagicMock()
        self.challenge.eab_handler.return_value.__enter__.return_value.key_file_load.return_value = {
            "another_kid": {
                "foo": "bar",
                "challenge": {"challenge_validation_disable": True},
            }
        }
        self.challenge.dbstore.challenge_lookup.return_value = {
            "foo": "bar",
            "authorization__order__account__eab_kid": "eab_kid",
        }
        self.challenge.dbstore.challenge_lookup.side_effect = None
        self.assertFalse(self.challenge._cvd_via_eabprofile_check("challenge_name"))

    def test_148_cvd_via_eabprofile_check(self):
        """test _cvd_via_eabprofile_check enabled cvd True"""
        self.challenge.eab_profiling = True
        self.challenge.eab_handler = MagicMock()
        self.challenge.eab_handler.return_value.__enter__.return_value.key_file_load.return_value = {
            "eab_kid": {"foo": "bar"},
            "another_kid": {
                "foo": "bar",
                "challenge": {"challenge_validation_disable": True},
            },
        }
        self.challenge.dbstore.challenge_lookup.return_value = {
            "foo": "bar",
            "authorization__order__account__eab_kid": "eab_kid",
        }
        self.challenge.dbstore.challenge_lookup.side_effect = None
        self.assertFalse(self.challenge._cvd_via_eabprofile_check("challenge_name"))

    @patch("acme_srv.challenge.Challenge._config_load")
    def test_149_enter(self, cfg_load):
        """test __enter__"""
        self.assertTrue(self.challenge.__enter__())
        self.assertTrue(cfg_load.called)

    @patch("acme_srv.challenge.fqdn_resolve")
    def test_150__forward_address_check(self, mock_resolv):
        """test _forward_address_check()"""
        self.challenge.source_address = "ip1"
        challenge_dic = {
            "authorization__type": "dns",
            "authorization__value": "value",
        }
        mock_resolv.return_value = [["ip1", "ip2"], "invalid"]
        self.assertEqual(
            (False, True),
            self.challenge._forward_address_check(challenge_dic=challenge_dic),
        )

    @patch("acme_srv.challenge.fqdn_resolve")
    def test_151__forward_address_check(self, mock_resolv):
        """test _forward_address_check() fqdn_resolv returns invalid but the ip is in the content"""
        self.challenge.source_address = "ip2"
        challenge_dic = {
            "authorization__type": "dns",
            "authorization__value": "value",
        }
        mock_resolv.return_value = [["ip1", "ip2"], True]
        self.assertEqual(
            (False, True),
            self.challenge._forward_address_check(challenge_dic=challenge_dic),
        )

    @patch("acme_srv.challenge.fqdn_resolve")
    def test_152__forward_address_check(self, mock_resolv):
        """test _forward_address_check() - ip check fails"""
        self.challenge.source_address = "ip3"
        challenge_dic = {
            "authorization__type": "dns",
            "authorization__value": "value",
        }
        mock_resolv.return_value = [["ip1", "ip2"], False]
        self.assertEqual(
            (False, True),
            self.challenge._forward_address_check(challenge_dic=challenge_dic),
        )

    @patch("acme_srv.challenge.fqdn_resolve")
    def test_154__forward_address_check(self, mock_resolv):
        """test _forward_address_check()"""
        self.challenge.source_address = "ip2"

        challenge_dic = {
            "authorization__type": "dns",
            "authorization__value": "value",
        }
        mock_resolv.return_value = [["ip1", "ip2"], False]
        self.assertEqual(
            (True, False),
            self.challenge._forward_address_check(challenge_dic=challenge_dic),
        )

    @patch("acme_srv.email_handler.EmailHandler.send")
    def test_155__email_send(self, mock_email):
        """test send"""
        self.assertFalse(self.challenge._email_send("to_address", "token1"))
        self.assertTrue(mock_email.called)

    def test_156__emailchallenge_keyauth_generate(self):
        """test _emailchallenge_keyauth_generate()"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "name": "name",
            "token": "token",
            "keyauthorization": "keyauthorization",
        }
        self.assertEqual(
            ("fXAhTLri1drJbQTLe4msBr9D9WQYs5Jybpj2D9UQBOw", "keyauthorization"),
            self.challenge._emailchallenge_keyauth_generate(
                "challenge_name", "token", "jwk_thumbprint"
            ),
        )

    def test_157__emailchallenge_keyauth_extract(self):
        """test _emailchallenge_keyauth_extract"""
        body = "foo"
        self.assertFalse(self.challenge._emailchallenge_keyauth_extract(body))

    def test_158__emailchallenge_keyauth_extract(self):
        """test _emailchallenge_keyauth_extract"""
        body = """
-----BEGIN ACME RESPONSE-----
4RQ8l7h50JB01xpDCoKZhe4XTY-ym-2Uxm7nz1LrBEA
-----END ACME RESPONSE-----
"""
        self.assertEqual(
            "4RQ8l7h50JB01xpDCoKZhe4XTY-ym-2Uxm7nz1LrBEA",
            self.challenge._emailchallenge_keyauth_extract(body),
        )

    def test_159__emailchallenge_keyauth_extract(self):
        """test _emailchallenge_keyauth_extract"""
        body = """-----BEGIN ACME RESPONSE-----\n4RQ8l7h50JB01xpDCoKZhe4XTY-ym-2Uxm7nz1LrBEA\n-----END ACME RESPONSE-----"""
        self.assertEqual(
            "4RQ8l7h50JB01xpDCoKZhe4XTY-ym-2Uxm7nz1LrBEA",
            self.challenge._emailchallenge_keyauth_extract(body),
        )

    def test_160__emailchallenge_keyauth_extract(self):
        """test _emailchallenge_keyauth_extract"""
        body = """-BEGIN ACME RESPONSE--\n4RQ8l7h50JB01xpDCoKZhe4XTY-ym-2Uxm7nz1LrBEA\n--END ACME RESPONSE--"""
        self.assertEqual(
            "4RQ8l7h50JB01xpDCoKZhe4XTY-ym-2Uxm7nz1LrBEA",
            self.challenge._emailchallenge_keyauth_extract(body),
        )

    @patch("acme_srv.challenge.EmailHandler")
    def test_161_validate_email_reply_challenge_success(self, mock_email_handler_cls):
        """Test _validate_email_reply_challenge returns (True, False) on success"""
        # Setup mock dbstore
        self.challenge.dbstore.challenge_lookup.return_value = {
            "name": "ch1",
            "token": "tok2",
            "keyauthorization": "tok1",
        }
        self.challenge.email_address = "test@example.com"
        self.challenge.email_identifier_support = True
        # Setup calculated keyauth to match extracted keyauth
        expected_keyauth = "expected_keyauth"
        with patch.object(
            self.challenge,
            "_emailchallenge_keyauth_generate",
            return_value=(expected_keyauth, "tok1"),
        ):
            with patch.object(
                self.challenge,
                "_emailchallenge_keyauth_extract",
                return_value=expected_keyauth,
            ):
                # Setup EmailHandler mock
                mock_email_handler = MagicMock()
                mock_email_handler.__enter__.return_value = mock_email_handler
                mock_email_handler.receive.return_value = {"body": "irrelevant"}
                mock_email_handler_cls.return_value = mock_email_handler

                result, invalid = self.challenge._validate_email_reply_challenge(
                    challenge_name="ch1",
                    _type="email",
                    email="test@example.com",
                    token="tok2",
                    jwk_thumbprint="thumb",
                )
                self.assertTrue(result)
                self.assertFalse(invalid)

    @patch("acme_srv.challenge.EmailHandler")
    def test_162_validate_email_reply_challenge_keyauth_mismatch(
        self, mock_email_handler_cls
    ):
        """Test _validate_email_reply_challenge returns (False, True) on keyauth mismatch"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "name": "ch1",
            "token": "tok2",
            "keyauthorization": "tok1",
        }
        self.challenge.email_address = "test@example.com"
        self.challenge.email_identifier_support = True
        with patch.object(
            self.challenge,
            "_emailchallenge_keyauth_generate",
            return_value=("expected_keyauth", "tok1"),
        ):
            with patch.object(
                self.challenge,
                "_emailchallenge_keyauth_extract",
                return_value="wrong_keyauth",
            ):
                mock_email_handler = MagicMock()
                mock_email_handler.__enter__.return_value = mock_email_handler
                mock_email_handler.receive.return_value = {"body": "irrelevant"}
                mock_email_handler_cls.return_value = mock_email_handler

                result, invalid = self.challenge._validate_email_reply_challenge(
                    challenge_name="ch1",
                    _type="email",
                    email="test@example.com",
                    token="tok2",
                    jwk_thumbprint="thumb",
                )
                self.assertFalse(result)
                self.assertTrue(invalid)

    @patch("acme_srv.challenge.EmailHandler")
    def test_163_validate_email_reply_challenge_no_email(self, mock_email_handler_cls):
        """Test _validate_email_reply_challenge returns (False, False) if no email received"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "name": "ch1",
            "token": "tok2",
            "keyauthorization": "tok1",
        }
        self.challenge.email_address = "test@example.com"
        self.challenge.email_identifier_support = True
        with patch.object(
            self.challenge,
            "_emailchallenge_keyauth_generate",
            return_value=("expected_keyauth", "tok1"),
        ):
            mock_email_handler = MagicMock()
            mock_email_handler.__enter__.return_value = mock_email_handler
            mock_email_handler.receive.return_value = None
            mock_email_handler_cls.return_value = mock_email_handler

            result, invalid = self.challenge._validate_email_reply_challenge(
                challenge_name="ch1",
                _type="email",
                email="test@example.com",
                token="tok2",
                jwk_thumbprint="thumb",
            )
            self.assertFalse(result)
            self.assertFalse(invalid)

    @patch("acme_srv.challenge.EmailHandler")
    def test_164_validate_email_reply_challenge_email_body_missing(
        self, mock_email_handler_cls
    ):
        """Test _validate_email_reply_challenge returns (False, False) if email body missing"""
        self.challenge.dbstore.challenge_lookup.return_value = {
            "name": "ch1",
            "token": "tok2",
            "keyauthorization": "tok1",
        }
        self.challenge.email_address = "test@example.com"
        self.challenge.email_identifier_support = True
        with patch.object(
            self.challenge,
            "_emailchallenge_keyauth_generate",
            return_value=("expected_keyauth", "tok1"),
        ):
            mock_email_handler = MagicMock()
            mock_email_handler.__enter__.return_value = mock_email_handler
            mock_email_handler.receive.return_value = {}
            mock_email_handler_cls.return_value = mock_email_handler

            result, invalid = self.challenge._validate_email_reply_challenge(
                challenge_name="ch1",
                _type="email",
                email="test@example.com",
                token="tok2",
                jwk_thumbprint="thumb",
            )
            self.assertFalse(result)
            self.assertFalse(invalid)

    @patch("acme_srv.challenge.EmailHandler")
    def test_165_email_filter_subject_match(self, mock_email_handler_cls):
        """Test _validate_email_reply_challenge processes only matching subject"""
        # Setup challenge lookup and keyauth generation
        self.challenge.dbstore.challenge_lookup.return_value = {
            "name": "ch1",
            "token": "tok2",
            "keyauthorization": "tok1",
        }
        self.challenge.email_address = "test@example.com"
        self.challenge.email_identifier_support = True
        expected_keyauth = "expected_keyauth"
        with patch.object(
            self.challenge,
            "_emailchallenge_keyauth_generate",
            return_value=(expected_keyauth, "tok1"),
        ):
            with patch.object(
                self.challenge,
                "_emailchallenge_keyauth_extract",
                return_value=expected_keyauth,
            ):
                # Setup EmailHandler mock
                mock_email_handler = MagicMock()
                mock_email_handler.__enter__.return_value = mock_email_handler
                # Simulate receive() returning an email with the correct subject
                mock_email_handler.receive.return_value = {
                    "subject": "ACME: tok1",
                    "body": "irrelevant",
                }
                mock_email_handler_cls.return_value = mock_email_handler

                result, invalid = self.challenge._validate_email_reply_challenge(
                    challenge_name="ch1",
                    _type="email",
                    email="test@example.com",
                    token="tok2",
                    jwk_thumbprint="thumb",
                )
                self.assertTrue(result)
                self.assertFalse(invalid)

    @patch("acme_srv.challenge.EmailHandler")
    def test_166_email_filter_subject_no_match(self, mock_email_handler_cls):
        """Test _validate_email_reply_challenge ignores non-matching subject"""
        self.challenge.email_address = "test@example.com"
        self.challenge.email_identifier_support = True
        self.challenge.dbstore.challenge_lookup.return_value = {
            "name": "ch1",
            "token": "tok2",
            "keyauthorization": "tok1",
        }
        expected_keyauth = "expected_keyauth"
        with patch.object(
            self.challenge,
            "_emailchallenge_keyauth_generate",
            return_value=(expected_keyauth, "tok1"),
        ):
            # Simulate receive() returning an email with a non-matching subject
            mock_email_handler = MagicMock()
            mock_email_handler.__enter__.return_value = mock_email_handler
            mock_email_handler.receive.return_value = {
                "subject": "Some other subject",
                "body": "irrelevant",
            }
            mock_email_handler_cls.return_value = mock_email_handler

            result, invalid = self.challenge._validate_email_reply_challenge(
                challenge_name="ch1",
                _type="email",
                email="test@example.com",
                token="tok2",
                jwk_thumbprint="thumb",
            )
            self.assertFalse(result)
            # self.assertFalse(invalid)

    def test_167_email_filter_subject_match(self):
        filter_string = "abc123"
        email_data = {"subject": "ACME: abc123", "body": "test"}
        result = self.challenge._email_filter(email_data, filter_string)
        self.assertEqual(result, email_data)

    def test_168_email_filter_subject_no_match(self):
        filter_string = "abc123"
        email_data = {"subject": "Other subject", "body": "test"}
        result = self.challenge._email_filter(email_data, filter_string)
        self.assertIsNone(result)

    @patch("acme_srv.challenge.Challenge._validate_http_challenge")
    def test_169_http_01_branch(self, mock_http):
        """Test _challenge_validate_loop for http-01"""
        mock_http.return_value = (True, False)
        challenge_dic = {
            "type": "http-01",
            "authorization__type": "dns",
            "authorization__value": "example.com",
            "token": "tok",
        }
        result, invalid = self.challenge._challenge_validate_loop(
            "ch1", challenge_dic, {}, "thumb"
        )
        mock_http.assert_called_once()
        self.assertTrue(result)
        self.assertFalse(invalid)

    @patch("acme_srv.challenge.Challenge._validate_dns_challenge")
    def test_170_dns_01_branch(self, mock_dns):
        """Test _challenge_validate_loop for dns-01"""
        mock_dns.return_value = (False, True)
        challenge_dic = {
            "type": "dns-01",
            "authorization__type": "dns",
            "authorization__value": "example.com",
            "token": "tok",
        }
        result, invalid = self.challenge._challenge_validate_loop(
            "ch2", challenge_dic, {}, "thumb"
        )
        mock_dns.assert_called_once()
        self.assertFalse(result)
        self.assertTrue(invalid)

    @patch("acme_srv.challenge.Challenge._validate_alpn_challenge")
    def test_171_tls_alpn_01_branch(self, mock_alpn):
        """Test _challenge_validate_loop for tls-alpn-01"""
        mock_alpn.return_value = (True, True)
        challenge_dic = {
            "type": "tls-alpn-01",
            "authorization__type": "dns",
            "authorization__value": "example.com",
            "token": "tok",
        }
        result, invalid = self.challenge._challenge_validate_loop(
            "ch3", challenge_dic, {}, "thumb"
        )
        mock_alpn.assert_called_once()
        self.assertTrue(result)
        self.assertTrue(invalid)

    @patch("acme_srv.challenge.Challenge._validate_tkauth_challenge")
    def test_172_tkauth_01_branch(self, mock_tkauth):
        """Test _challenge_validate_loop for tkauth-01"""
        self.challenge.tnauthlist_support = True  # For tkauth-01 branch
        mock_tkauth.return_value = (False, False)
        challenge_dic = {
            "type": "tkauth-01",
            "authorization__type": "dns",
            "authorization__value": "example.com",
            "token": "tok",
        }
        payload = {"foo": "bar"}
        result, invalid = self.challenge._challenge_validate_loop(
            "ch4", challenge_dic, payload, "thumb"
        )
        mock_tkauth.assert_called_once()
        self.assertFalse(result)
        self.assertFalse(invalid)

    @patch("acme_srv.challenge.Challenge._validate_tkauth_challenge")
    def test_173_tkauth_01_branch(self, mock_tkauth):
        """Test _challenge_validate_loop for tkauth-01"""
        mock_tkauth.return_value = (False, False)
        challenge_dic = {
            "type": "tkauth-01",
            "authorization__type": "dns",
            "authorization__value": "example.com",
            "token": "tok",
        }
        payload = {"foo": "bar"}
        result, invalid = self.challenge._challenge_validate_loop(
            "ch4", challenge_dic, payload, "thumb"
        )
        self.assertFalse(mock_tkauth.called)
        self.assertFalse(result)
        self.assertTrue(invalid)

    @patch("acme_srv.challenge.Challenge._validate_email_reply_challenge")
    def test_174_email_reply_00_branch(self, mock_email):
        """Test _challenge_validate_loop for email-reply-00"""
        mock_email.return_value = (True, False)
        challenge_dic = {
            "type": "email-reply-00",
            "authorization__type": "email",
            "authorization__value": "user@example.com",
            "token": "tok",
        }
        result, invalid = self.challenge._challenge_validate_loop(
            "ch5", challenge_dic, {}, "thumb"
        )
        mock_email.assert_called_once()
        self.assertTrue(result)
        self.assertFalse(invalid)

    def test_175_unknown_type_branch(self):
        """Test _challenge_validate_loop for unknown type"""
        challenge_dic = {
            "type": "unknown-type",
            "authorization__type": "dns",
            "authorization__value": "example.com",
            "token": "tok",
        }
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            result, invalid = self.challenge._challenge_validate_loop(
                "ch6", challenge_dic, {}, "thumb"
            )

        self.assertFalse(result)
        self.assertTrue(invalid)
        self.assertIn(
            'ERROR:test_a2c:Unknown challenge type "unknown-type". Setting check result to False',
            lcm.output,
        )

    def test_176_email_identifier_support_disabled(self):
        """Should return False if email_identifier_support is False"""
        # self.challenge.email_identifier_support = False
        self.assertFalse(
            self.challenge._email_reply_challenge_create("email", "user@example.com")
        )
        self.assertFalse(
            self.challenge._email_reply_challenge_create("dns", "user@example.com")
        )

    def test_177_id_type_email(self):
        """Should return True if id_type is 'email' and support enabled"""
        self.challenge.email_identifier_support = True
        self.assertTrue(
            self.challenge._email_reply_challenge_create("email", "user@example.com")
        )

    def test_178_id_type_dns_with_at(self):
        """Should return True if id_type is 'dns' and value contains '@'"""
        self.challenge.email_identifier_support = True
        self.assertTrue(
            self.challenge._email_reply_challenge_create("dns", "user@example.com")
        )

    def test_179_id_type_dns_without_at(self):
        """Should return False if id_type is 'dns' and value does not contain '@'"""
        self.challenge.email_identifier_support = True
        self.assertFalse(
            self.challenge._email_reply_challenge_create("dns", "example.com")
        )

    def test_180_id_type_other(self):
        """Should return False for other id_types"""
        self.challenge.email_identifier_support = True
        self.assertFalse(
            self.challenge._email_reply_challenge_create("ip", "192.0.2.1")
        )
        self.assertFalse(self.challenge._email_reply_challenge_create("other", "foo"))


if __name__ == "__main__":
    unittest.main()
