#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for django_handler"""

from __future__ import annotations

import importlib
import json
import logging
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_TEST_DJANGO_DB = Path(tempfile.mkstemp(suffix="-a2c-django-handler.sqlite3")[1])


def _bootstrap_django() -> None:
    """Configure Django sqlite test DB once for this module."""
    import django
    from django.conf import settings

    if settings.configured:
        return
    settings.configure(
        INSTALLED_APPS=[
            "django.contrib.contenttypes",
            "django.contrib.auth",
            "acme2certifier.django_app.apps.AcmeSrvConfig",
        ],
        DATABASES={
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": str(_TEST_DJANGO_DB),
            }
        },
        USE_TZ=True,
        SECRET_KEY="test-a2c-django-handler",
        DEFAULT_AUTO_FIELD="django.db.models.AutoField",
        TIME_ZONE="UTC",
    )
    django.setup()


_bootstrap_django()

from acme2certifier.dbhandlers import django_handler as dh_mod  # noqa: E402
from acme2certifier.dbhandlers.django_handler import DBstore, initialize  # noqa: E402
from acme2certifier.django_app.models import (  # noqa: E402
    Account,
    Authorization,
    Cahandler,
    Certificate,
    Challenge,
    Cliaccount,
    Housekeeping,
    Nonce,
    Order,
    Status,
)


def _jwk_str(kid: str = "k1") -> str:
    return json.dumps({"kty": "RSA", "kid": kid, "n": "n", "e": "AQAB"})


class TestDjangoHandler(unittest.TestCase):
    """test class for django_handler.DBstore"""

    @classmethod
    def setUpClass(cls) -> None:
        from django.core.management import call_command

        call_command("migrate", interactive=False, verbosity=0, run_syncdb=True)
        if Status.objects.count() != 8:
            call_command("loaddata", "status", verbosity=0)
        elif not Housekeeping.objects.filter(name="dbversion").exists():
            Housekeeping.objects.create(name="dbversion", value="0.41")

    def setUp(self) -> None:
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self.dbstore = DBstore(False, self.logger)
        self._clean_db()

    def tearDown(self) -> None:
        self._clean_db()

    def _clean_db(self) -> None:
        Nonce.objects.all().delete()
        Certificate.objects.all().delete()
        Challenge.objects.all().delete()
        Authorization.objects.all().delete()
        Order.objects.all().delete()
        Account.objects.all().delete()
        Cliaccount.objects.all().delete()
        Cahandler.objects.all().delete()
        Housekeeping.objects.exclude(name="dbversion").delete()
        if Status.objects.count() != 8:
            from django.core.management import call_command

            call_command("loaddata", "status", verbosity=0)
        if not Housekeeping.objects.filter(name="dbversion").exists():
            Housekeeping.objects.create(name="dbversion", value="0.41")

    def _seed_account(self, name: str = "acct1", jwk: str | None = None) -> Account:
        return Account.objects.create(
            name=name,
            jwk=jwk or _jwk_str(name),
            alg="RS256",
            contact="mailto:a@example.com",
            status_id=5,
        )

    def _seed_order(self, account: Account, name: str = "ord1") -> Order:
        return Order.objects.create(
            name=name,
            account=account,
            identifiers='[{"type":"dns","value":"ex.com"}]',
            status_id=2,
            expires=9999999999,
        )

    def _seed_authz(self, order: Order, name: str = "authz1") -> Authorization:
        return Authorization.objects.create(
            name=name,
            order=order,
            type="dns",
            value="ex.com",
            status_id=2,
            expires=9999999999,
        )

    def test_001_default(self) -> None:
        """default test which always passes"""
        self.assertEqual("foo", "foo")

    def test_002_init_and_type(self) -> None:
        """test DBstore.__init__ and type attribute"""
        self.assertEqual("django", self.dbstore.type)
        self.assertIs(self.dbstore.logger, self.logger)

    def test_003_initialize_returns_major(self) -> None:
        """test initialize() returns Django major version"""
        self.assertIsInstance(initialize(), int)
        self.assertGreaterEqual(initialize(), 3)

    def test_004_modify_key(self) -> None:
        """test DBstore._modify_key()"""
        self.assertEqual("expires", self.dbstore._modify_key("expires", "LIKE"))
        self.assertEqual("expires__lte", self.dbstore._modify_key("expires", "<="))

    def test_005_status_getinstance(self) -> None:
        """test DBstore._status_getinstance()"""
        status = self.dbstore._status_getinstance("valid", "name")
        self.assertEqual("valid", status.name)

    def test_006_account_add_new(self) -> None:
        """test DBstore.account_add() creates account"""
        aname, created = self.dbstore.account_add(
            {
                "name": "acctNew",
                "jwk": _jwk_str("new"),
                "alg": "RS256",
                "contact": "mailto:n@example.com",
                "status": "valid",
                "eab_kid": "",
            }
        )
        self.assertEqual("acctNew", aname)
        self.assertTrue(created)
        self.assertTrue(Account.objects.filter(name="acctNew").exists())

    def test_007_account_add_existing_jwk(self) -> None:
        """test DBstore.account_add() returns existing when jwk matches"""
        self._seed_account("acctDup", _jwk_str("dup"))
        aname, created = self.dbstore.account_add(
            {
                "name": "other",
                "jwk": _jwk_str("dup"),
                "alg": "RS256",
                "contact": "mailto:x@example.com",
            }
        )
        self.assertEqual("acctDup", aname)
        self.assertFalse(created)

    def test_008_account_lookup_found(self) -> None:
        """test DBstore.account_lookup() hit"""
        self._seed_account("acctL")
        result = self.dbstore.account_lookup("name", "acctL")
        self.assertIsNotNone(result)
        self.assertEqual("acctL", result["name"])

    def test_009_account_lookup_miss(self) -> None:
        """test DBstore.account_lookup() miss"""
        self.assertIsNone(self.dbstore.account_lookup("name", "missing"))

    def test_010_account_delete(self) -> None:
        """test DBstore.account_delete()"""
        self._seed_account("acctDel")
        self.dbstore.account_delete("acctDel")
        self.assertFalse(Account.objects.filter(name="acctDel").exists())

    def test_011_account_update(self) -> None:
        """test DBstore.account_update()"""
        self._seed_account("acctUp")
        rid = self.dbstore.account_update(
            {
                "name": "acctUp",
                "jwk": _jwk_str("up"),
                "alg": "ES256",
                "contact": "mailto:u@example.com",
            }
        )
        self.assertIsInstance(rid, int)
        self.assertEqual("ES256", Account.objects.get(name="acctUp").alg)

    def test_012_accountlist_get(self) -> None:
        """test DBstore.accountlist_get()"""
        self._seed_account("acctList")
        vlist, rows = self.dbstore.accountlist_get()
        self.assertIn("name", vlist)
        self.assertTrue(any(r["name"] == "acctList" for r in rows))

    def test_013_account_getinstance(self) -> None:
        """test DBstore._account_getinstance()"""
        self._seed_account("acctInst")
        obj = self.dbstore._account_getinstance("acctInst")
        self.assertEqual("acctInst", obj.name)

    def test_014_order_add_and_getinstance(self) -> None:
        """test DBstore.order_add() and _order_getinstance()"""
        self._seed_account("acctOrd")
        oid = self.dbstore.order_add(
            {
                "name": "ordAdd",
                "account": "acctOrd",
                "status": 2,
                "identifiers": '[{"type":"dns","value":"a.com"}]',
                "expires": 1,
            }
        )
        self.assertIsInstance(oid, int)
        order = self.dbstore._order_getinstance("ordAdd", "name")
        self.assertEqual("ordAdd", order.name)

    def test_015_order_lookup_found(self) -> None:
        """test DBstore.order_lookup() hit with status rename"""
        acct = self._seed_account("acctOL")
        self._seed_order(acct, "ordLook")
        result = self.dbstore.order_lookup("name", "ordLook")
        self.assertIsNotNone(result)
        self.assertEqual("pending", result["status"])

    def test_016_order_lookup_miss(self) -> None:
        """test DBstore.order_lookup() miss"""
        self.assertIsNone(self.dbstore.order_lookup("name", "nope"))

    def test_017_order_lookup_account_name_branch(self) -> None:
        """test DBstore.order_lookup() account_name rename branch via mock"""
        values_qs = MagicMock()
        values_qs.__getitem__.return_value = [
            {"account_name": "acctX", "account__name": "acctX", "name": "o1"}
        ]
        with patch.object(Order.objects, "filter") as mock_filter:
            mock_filter.return_value.values.return_value = values_qs
            result = self.dbstore.order_lookup("name", "o1", vlist=["account_name"])
        self.assertEqual("acctX", result["account"])
        self.assertNotIn("account__name", result)

    def test_018_order_update(self) -> None:
        """test DBstore.order_update()"""
        acct = self._seed_account("acctOU")
        self._seed_order(acct, "ordUp")
        self.dbstore.order_update({"name": "ordUp", "status": "ready"})
        self.assertEqual(3, Order.objects.get(name="ordUp").status_id)

    def test_019_order_update_if_status(self) -> None:
        """conditional status update returns 1 then 0"""
        acct = self._seed_account("acctCAS")
        self._seed_order(acct, "ordCAS")
        self.dbstore.order_update({"name": "ordCAS", "status": "ready"})
        self.assertEqual(
            1, self.dbstore.order_update_if_status("ordCAS", "processing", "ready")
        )
        self.assertEqual(4, Order.objects.get(name="ordCAS").status_id)
        self.assertEqual(
            0, self.dbstore.order_update_if_status("ordCAS", "processing", "ready")
        )

    def test_020_orders_invalid_search(self) -> None:
        """test DBstore.orders_invalid_search()"""
        acct = self._seed_account("acctOIS")
        Order.objects.create(
            name="ordInv",
            account=acct,
            identifiers="[]",
            status_id=3,
            expires=10,
        )
        rows = list(
            self.dbstore.orders_invalid_search(
                "name",
                "ordInv",
                vlist=["id", "name", "status__id"],
                operant="=",
            )
        )
        self.assertEqual(1, len(rows))
        self.assertEqual("ordInv", rows[0]["name"])

    def test_021_authorization_add_lookup_update(self) -> None:
        """test authorization_add / lookup / update / getinstance"""
        acct = self._seed_account("acctAz")
        order = self._seed_order(acct, "ordAz")
        aid = self.dbstore.authorization_add(
            {
                "name": "azAdd",
                "order": order.id,
                "type": "dns",
                "value": "ex.com",
                "status": "pending",
                "expires": 1,
            }
        )
        self.assertIsInstance(aid, int)
        az = self.dbstore._authorization_getinstance("azAdd")
        self.assertEqual("azAdd", az.name)
        rows = self.dbstore.authorization_lookup(
            "name", "azAdd", vlist=["type", "value"]
        )
        self.assertEqual(1, len(rows))
        self.assertEqual("dns", rows[0]["type"])
        rid = self.dbstore.authorization_update({"name": "azAdd", "status": "valid"})
        self.assertIsInstance(rid, int)
        self.assertEqual(5, Authorization.objects.get(name="azAdd").status_id)

    def test_022_authorizations_expired_search(self) -> None:
        """test DBstore.authorizations_expired_search()"""
        acct = self._seed_account("acctAzS")
        order = self._seed_order(acct, "ordAzS")
        Authorization.objects.create(
            name="azPend",
            order=order,
            type="dns",
            value="a.com",
            status_id=2,
            expires=5,
        )
        Authorization.objects.create(
            name="azExp",
            order=order,
            type="dns",
            value="b.com",
            status_id=6,
            expires=5,
        )
        rows = list(
            self.dbstore.authorizations_expired_search(
                "expires",
                5,
                vlist=["id", "name", "status__name"],
                operant="=",
            )
        )
        names = {r["name"] for r in rows}
        self.assertIn("azPend", names)
        self.assertNotIn("azExp", names)

    def test_023_authorization_update_django3_sqlite(self) -> None:
        """test authorization_update Django<4 sqlite immediate branch"""
        acct = self._seed_account("acctAz3")
        order = self._seed_order(acct, "ordAz3")
        self._seed_authz(order, "az3")
        mock_atomic = MagicMock()
        mock_atomic.return_value.__enter__ = MagicMock(return_value=None)
        mock_atomic.return_value.__exit__ = MagicMock(return_value=False)
        with (
            patch.object(dh_mod, "DJANGO_VERSION", 3),
            patch.object(dh_mod.transaction, "atomic", mock_atomic),
        ):
            rid = self.dbstore.authorization_update(
                {"name": "az3", "status": "valid", "token": "tok"}
            )
        self.assertIsInstance(rid, int)
        mock_atomic.assert_any_call(immediate=True)

    def test_024_cahandler_add_lookup(self) -> None:
        """test cahandler_add / cahandler_lookup"""
        cname, created = self.dbstore.cahandler_add(
            {"name": "ca1", "value1": "v1", "value2": "v2"}
        )
        self.assertEqual("ca1", cname)
        self.assertTrue(created)
        cname2, created2 = self.dbstore.cahandler_add(
            {"name": "ca1", "value1": "x", "value2": "y"}
        )
        self.assertEqual("ca1", cname2)
        self.assertFalse(created2)
        result = self.dbstore.cahandler_lookup("name", "ca1")
        self.assertEqual("v1", result["value1"])
        self.assertIsNone(self.dbstore.cahandler_lookup("name", "missing"))

    def test_025_challenge_add_lookup_update_search(self) -> None:
        """test challenge_add / lookup / update / search"""
        acct = self._seed_account("acctCh")
        order = self._seed_order(acct, "ordCh")
        self._seed_authz(order, "azCh")
        cid = self.dbstore.challenge_add(
            "ex.com",
            "http-01",
            {
                "name": "ch1",
                "authorization": "azCh",
                "type": "http-01",
                "token": "tok1",
                "status": 2,
                "expires": 1,
            },
        )
        self.assertIsInstance(cid, int)
        result = self.dbstore.challenge_lookup(
            "name",
            "ch1",
            vlist=["type", "token", "status__name", "authorization__name"],
        )
        self.assertEqual("http-01", result["type"])
        self.assertEqual("pending", result["status"])
        self.assertEqual("azCh", result["authorization"])
        self.assertIsNone(self.dbstore.challenge_lookup("name", "missing"))
        self.dbstore.challenge_update(
            {"name": "ch1", "status": "valid", "keyauthorization": "ka"}
        )
        self.assertEqual(5, Challenge.objects.get(name="ch1").status_id)
        rows = list(
            self.dbstore.challenges_search(
                "name", "ch1", vlist=["name", "type", "status__name", "token"]
            )
        )
        self.assertEqual(1, len(rows))

    def test_026_challenge_add_django3_sqlite(self) -> None:
        """test challenge_add Django<4 sqlite immediate branch"""
        acct = self._seed_account("acctCh3")
        order = self._seed_order(acct, "ordCh3")
        self._seed_authz(order, "azCh3")
        mock_atomic = MagicMock()
        mock_atomic.return_value.__enter__ = MagicMock(return_value=None)
        mock_atomic.return_value.__exit__ = MagicMock(return_value=False)
        with (
            patch.object(dh_mod, "DJANGO_VERSION", 3),
            patch.object(dh_mod.transaction, "atomic", mock_atomic),
        ):
            cid = self.dbstore.challenge_add(
                "ex.com",
                "http-01",
                {
                    "name": "ch3",
                    "authorization": "azCh3",
                    "type": "http-01",
                    "token": "tok3",
                    "status": 2,
                    "expires": 1,
                },
            )
        self.assertIsInstance(cid, int)
        mock_atomic.assert_any_call(immediate=True)

    def test_027_certificate_add_lookup_delete_list(self) -> None:
        """test certificate_add / lookup / delete / list / search / account_check"""
        acct = self._seed_account("acctCert")
        order = self._seed_order(acct, "ordCert")
        cid = self.dbstore.certificate_add(
            {
                "name": "cert1",
                "order": "ordCert",
                "csr": "csr-data",
                "cert": "cert-pem",
                "cert_raw": "raw-cert-bytes",
            }
        )
        self.assertIsInstance(cid, int)
        result = self.dbstore.certificate_lookup("name", "cert1")
        self.assertEqual("ordCert", result["order"])
        self.assertIsNone(self.dbstore.certificate_lookup("name", "missing"))
        checked = self.dbstore.certificate_account_check("acctCert", "raw-cert-bytes")
        self.assertEqual("ordCert", checked)
        checked2 = self.dbstore.certificate_account_check(None, "raw-cert-bytes")
        self.assertEqual("ordCert", checked2)
        checked3 = self.dbstore.certificate_account_check("wrong", "raw-cert-bytes")
        self.assertIsNone(checked3)
        self.assertIsNone(
            self.dbstore.certificate_account_check("acctCert", "no-such-cert")
        )
        vlist, rows = self.dbstore.certificatelist_get()
        self.assertIn("cert_raw", vlist)
        self.assertTrue(any(r["name"] == "cert1" for r in rows))
        search_rows = list(
            self.dbstore.certificates_search(
                "name", "cert1", vlist=["name", "csr"], operant=None
            )
        )
        self.assertEqual(1, len(search_rows))
        self.dbstore.certificate_delete("name", "cert1")
        self.assertFalse(Certificate.objects.filter(name="cert1").exists())

    def test_028_cli_jwk_and_permissions(self) -> None:
        """test cli_jwk_load / cli_permissions_get"""
        self.assertEqual({}, self.dbstore.cli_jwk_load("missing"))
        self.assertEqual({}, self.dbstore.cli_permissions_get("missing"))
        Cliaccount.objects.create(
            name="cli1",
            jwk=_jwk_str("cli"),
            contact="mailto:c@example.com",
            cliadmin=True,
            reportadmin=False,
            certificateadmin=True,
        )
        jwk = self.dbstore.cli_jwk_load("cli1")
        self.assertEqual("RSA", jwk["kty"])
        perms = self.dbstore.cli_permissions_get("cli1")
        self.assertTrue(perms["cliadmin"])
        self.assertFalse(perms["reportadmin"])

    def test_029_cli_jwk_load_bytes(self) -> None:
        """test cli_jwk_load bytes.decode path via mocked ORM row"""
        values_qs = MagicMock()
        values_qs.__getitem__.return_value = [{"jwk": b'{"kty":"EC","crv":"P-256"}'}]
        with patch.object(Cliaccount.objects, "filter") as mock_filter:
            mock_filter.return_value.values.return_value = values_qs
            jwk = self.dbstore.cli_jwk_load("cliBytes")
        self.assertEqual("EC", jwk["kty"])

    def test_030_cli_jwk_load_decode_error(self) -> None:
        """test cli_jwk_load logs ERROR then falls back to json.loads(str)"""
        Cliaccount.objects.create(
            name="cliBad",
            jwk='{"kty":"OK"}',
            contact="mailto:bad@example.com",
        )
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            jwk2 = self.dbstore.cli_jwk_load("cliBad")
        self.assertEqual("OK", jwk2["kty"])
        self.assertTrue(
            any(
                "Failed to decode JWK from cliaccounts table" in line
                for line in lcm.output
            )
        )

    def test_031_dbversion_and_hkparameter(self) -> None:
        """test dbversion_get / hkparameter_add / hkparameter_get"""
        version, tool = self.dbstore.dbversion_get()
        self.assertEqual("a2c-django-update", tool)
        self.assertIsNotNone(version)
        self.dbstore.hkparameter_add({"name": "foo", "value": "bar"})
        self.assertEqual("bar", self.dbstore.hkparameter_get("foo"))
        self.assertIsNone(self.dbstore.hkparameter_get("missing-param"))
        Housekeeping.objects.filter(name="dbversion").delete()
        self.assertEqual((None, "a2c-django-update"), self.dbstore.dbversion_get())

    def test_032_jwk_load(self) -> None:
        """test DBstore.jwk_load() str and bytes paths"""
        self.assertEqual({}, self.dbstore.jwk_load("missing"))
        self._seed_account("acctJwk", _jwk_str("jwk"))
        jwk = self.dbstore.jwk_load("acctJwk")
        self.assertEqual("RS256", jwk["alg"])
        self.assertEqual("RSA", jwk["kty"])
        values_qs = MagicMock()
        values_qs.__getitem__.return_value = [{"jwk": b'{"kty":"EC"}', "alg": "ES256"}]
        with patch.object(Account.objects, "filter") as mock_filter:
            mock_filter.return_value.values.return_value = values_qs
            jwk2 = self.dbstore.jwk_load("acctJwk")
        self.assertEqual("EC", jwk2["kty"])
        self.assertEqual("ES256", jwk2["alg"])

    def test_033_nonce_ops(self) -> None:
        """test nonce_add / check / delete / consume / delete_bulk / search_by_timestamp"""
        rid = self.dbstore.nonce_add("n1")
        self.assertIsInstance(rid, int)
        self.assertTrue(self.dbstore.nonce_check("n1"))
        self.assertFalse(self.dbstore.nonce_check("missing"))
        self.dbstore.nonce_add("n2")
        self.dbstore.nonce_add("n3")
        self.assertEqual(0, self.dbstore.nonce_delete_bulk([]))
        deleted = self.dbstore.nonce_delete_bulk(["n1", "n3"])
        self.assertGreaterEqual(deleted, 2)
        self.assertFalse(self.dbstore.nonce_check("n1"))
        self.assertTrue(self.dbstore.nonce_check("n2"))
        self.assertEqual(1, self.dbstore.nonce_consume("n2"))
        self.assertFalse(self.dbstore.nonce_check("n2"))
        self.assertEqual(0, self.dbstore.nonce_consume("n2"))
        self.dbstore.nonce_add("nOld")
        found = self.dbstore.nonce_search_by_timestamp(int(time.time()) + 3600)
        self.assertIn("nOld", found)
        found_empty = self.dbstore.nonce_search_by_timestamp(0)
        self.assertEqual([], found_empty)

    def test_034_nonce_unique(self) -> None:
        """test duplicate nonce insert is rejected after unique constraint"""
        self.dbstore.nonce_add("unique-n")
        with self.assertRaises(Exception):
            self.dbstore.nonce_add("unique-n")

    def test_035_certificate_add_without_order(self) -> None:
        """test certificate_add without order key"""
        # order FK is required by model; create with order via ORM then update path
        # covers branch where "order" not in data_dic by mocking update_or_create
        mock_obj = MagicMock()
        mock_obj.id = 99
        with patch.object(
            Certificate.objects,
            "update_or_create",
            return_value=(mock_obj, True),
        ) as mock_uoc:
            rid = self.dbstore.certificate_add({"name": "certNoOrd", "csr": "c"})
        self.assertEqual(99, rid)
        mock_uoc.assert_called_once()
        self.assertNotIn(
            "order",
            mock_uoc.call_args.kwargs.get(
                "defaults", mock_uoc.call_args[1] if len(mock_uoc.call_args) > 1 else {}
            ),
        )

    def test_036_challenge_update_without_status(self) -> None:
        """test challenge_update without status key"""
        acct = self._seed_account("acctCu")
        order = self._seed_order(acct, "ordCu")
        az = self._seed_authz(order, "azCu")
        Challenge.objects.create(
            name="chCu",
            authorization=az,
            type="http-01",
            token="t",
            status_id=2,
        )
        self.dbstore.challenge_update({"name": "chCu", "keyauthorization": "ka2"})
        self.assertEqual("ka2", Challenge.objects.get(name="chCu").keyauthorization)

    def test_037_order_update_without_status(self) -> None:
        """test order_update without status key"""
        acct = self._seed_account("acctOu2")
        self._seed_order(acct, "ordOu2")
        self.dbstore.order_update({"name": "ordOu2", "expires": 42})
        self.assertEqual(42, Order.objects.get(name="ordOu2").expires)

    def test_038_authorization_add_without_optional(self) -> None:
        """test authorization_add without order/status keys"""
        acct = self._seed_account("acctAzO")
        order = self._seed_order(acct, "ordAzO")
        # Must still satisfy FK via defaults path using existing order instance name
        # Use ORM seed then update_or_create path without status/order in dic via mock
        mock_obj = MagicMock()
        mock_obj.id = 77
        with patch.object(
            Authorization.objects,
            "update_or_create",
            return_value=(mock_obj, True),
        ):
            rid = self.dbstore.authorization_add(
                {"name": "azBare", "type": "dns", "value": "x"}
            )
        self.assertEqual(77, rid)
        self.assertEqual(order.name, "ordAzO")  # keep seed referenced

    def test_039_modify_key_lte_branch_in_search(self) -> None:
        """test certificates_search with <= operant"""
        acct = self._seed_account("acctLte")
        order = self._seed_order(acct, "ordLte")
        Certificate.objects.create(
            name="certLte",
            order=order,
            expire_uts=100,
            cert_raw="raw",
        )
        rows = list(
            self.dbstore.certificates_search(
                "expire_uts", 100, vlist=["name"], operant="<="
            )
        )
        self.assertTrue(any(r["name"] == "certLte" for r in rows))

    def test_040_model_unicode_methods(self) -> None:
        """test Django model __unicode__() helpers"""
        nonce = Nonce.objects.create(nonce="n-unicode")
        self.assertEqual("n-unicode", nonce.__unicode__())
        status = Status.objects.get(name="valid")
        self.assertEqual("valid", status.__unicode__())
        account = self._seed_account(name="acct-uni")
        self.assertEqual("mailto:a@example.com", account.__unicode__())
        order = self._seed_order(account, name="ord-uni")
        self.assertEqual("ord-uni", order.__unicode__())
        authz = self._seed_authz(order, name="authz-uni")
        self.assertEqual("authz-uni", authz.__unicode__())
        chall = Challenge.objects.create(
            name="chall-uni",
            authorization=authz,
            type="http-01",
            token="tok",
            status_id=2,
        )
        self.assertEqual("chall-uni", chall.__unicode__())
        cert = Certificate.objects.create(name="cert-uni", order=order)
        self.assertEqual("cert-uni", cert.__unicode__())


class TestDjangoHandlerInitializeReload(unittest.TestCase):
    """cover initialize monkey_patches import for Django < 4 via reload"""

    def test_041_initialize_loads_monkey_patches_on_django3(self) -> None:
        """reload django_handler with Django major < 4 to hit monkey_patches import"""
        saved = {
            key: sys.modules.get(key)
            for key in (
                "django",
                "django.conf",
                "django.db",
                "django.db.transaction",
                "django.db.models",
                "acme2certifier.django_app.models",
                "acme2certifier.acme_srv.monkey_patches",
                "acme2certifier.dbhandlers.django_handler",
            )
        }
        try:
            mock_django = MagicMock()
            mock_django.VERSION = (3, 2, 0)
            mock_settings = MagicMock()
            mock_settings.configured = True
            mock_transaction = MagicMock()
            mock_queryset = MagicMock()
            monkey = MagicMock()
            mock_models = MagicMock()
            for name in (
                "Account",
                "Authorization",
                "Cahandler",
                "Certificate",
                "Challenge",
                "Cliaccount",
                "Housekeeping",
                "Nonce",
                "Order",
                "Status",
            ):
                setattr(mock_models, name, MagicMock())

            sys.modules["django"] = mock_django
            sys.modules["django.conf"] = MagicMock(settings=mock_settings)
            sys.modules["django.db"] = MagicMock(transaction=mock_transaction)
            sys.modules["django.db.transaction"] = mock_transaction
            sys.modules["django.db.models"] = MagicMock(QuerySet=mock_queryset)
            sys.modules["acme2certifier.django_app.models"] = mock_models
            sys.modules["acme2certifier.acme_srv.monkey_patches"] = monkey
            sys.modules.pop("acme2certifier.dbhandlers.django_handler", None)

            with patch.dict(os.environ, {}, clear=False):
                reloaded = importlib.import_module(
                    "acme2certifier.dbhandlers.django_handler"
                )
            self.assertEqual(3, reloaded.DJANGO_VERSION)
            self.assertIn("acme2certifier.acme_srv.monkey_patches", sys.modules)
        finally:
            sys.modules.pop("acme2certifier.dbhandlers.django_handler", None)
            for key, val in saved.items():
                if val is None:
                    sys.modules.pop(key, None)
                else:
                    sys.modules[key] = val
            # restore the real module for remaining suites
            importlib.import_module("acme2certifier.dbhandlers.django_handler")


if __name__ == "__main__":
    unittest.main()
