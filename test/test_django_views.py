#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for django_app.views"""

# pylint: disable=C0415, R0904, W0212
import importlib
import logging
import sys
import tempfile
import unittest
from io import StringIO
from unittest.mock import MagicMock, patch

import django
from django.conf import settings
from django.test import RequestFactory


def _bootstrap_django() -> None:
    if settings.configured:
        return
    settings.configure(
        INSTALLED_APPS=[
            "django.contrib.contenttypes",
            "django.contrib.auth",
            "acme2certifier.django_app.apps.AcmeSrvConfig",
        ],
        DATABASES={
            "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}
        },
        SECRET_KEY="test-django-views",
        USE_TZ=True,
        ROOT_URLCONF="acme2certifier.django_app.urls",
        MIDDLEWARE=[],
        ALLOWED_HOSTS=["*"],
    )
    django.setup()


_bootstrap_django()

_VIEWS = "acme2certifier.django_app.views"


def _ok(data=None, header=None, code=200):
    return {
        "code": code,
        "data": data if data is not None else {"ok": True},
        "header": header if header is not None else {"Replay-Nonce": "n1"},
    }


class TestDjangoViews(unittest.TestCase):
    """cover django_app.views helpers and HTTP handlers"""

    def setUp(self) -> None:
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self.rf = RequestFactory()
        self._tmpdir = tempfile.mkdtemp(prefix="a2c_dj_views_")
        self._env = patch.dict(
            "os.environ", {"ACME2CERTIFIER_BASE_DIR": self._tmpdir}, clear=False
        )
        self._env.start()
        # handler suite may have configured Django without ALLOWED_HOSTS
        settings.ALLOWED_HOSTS = ["*", "testserver", "localhost"]

        mock_hk = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__enter__.return_value = mock_hk
        mock_cm.__exit__.return_value = False

        sys.modules.pop(_VIEWS, None)
        with (
            patch(
                "acme2certifier.acme_srv.housekeeping.Housekeeping",
                return_value=mock_cm,
            ),
            patch("acme2certifier.acme_srv.helper.config_check"),
            patch(
                "acme2certifier.acme_srv.helper.legacy_acme_get_load",
                return_value=False,
            ),
            patch("acme2certifier.acme_srv.helper.log_loaded_acme_srv_cfg"),
            patch("acme2certifier.acme_srv.db_handler.log_active_db_handler"),
        ):
            self.views = importlib.import_module(_VIEWS)

    def tearDown(self) -> None:
        self._env.stop()
        import shutil

        shutil.rmtree(self._tmpdir, ignore_errors=True)
        sys.modules.pop(_VIEWS, None)

    def _cm(self, **methods):
        inst = MagicMock()
        for name, ret in methods.items():
            getattr(inst, name).return_value = ret
        cm = MagicMock()
        cm.__enter__.return_value = inst
        cm.__exit__.return_value = False
        return cm, inst

    def _meta(self, request):
        request.META.setdefault("REMOTE_ADDR", "127.0.0.1")
        request.META.setdefault("PATH_INFO", request.path)
        return request

    def test_001_handle_exception_prints(self) -> None:
        """handle_exception prints type/value/traceback"""
        with patch("sys.stdout", new_callable=StringIO) as out:
            self.views.handle_exception(ValueError, ValueError("x"), "tb")
        text = out.getvalue()
        self.assertIn("My Error Information", text)
        self.assertIn("Type:", text)
        self.assertIn("Value:", text)
        self.assertIn("Traceback:", text)

    def test_002_pretty_request(self) -> None:
        """pretty_request formats HTTP-ish dump including HTTP_* headers"""
        request = self.rf.post(
            "/acct",
            data=b"body-bytes",
            content_type="application/jose+json",
            HTTP_FOO_BAR="baz",
        )
        self._meta(request)
        dump = self.views.pretty_request(request)
        self.assertIn("POST HTTP/1.1", dump)
        self.assertIn("Foo-Bar: baz", dump)
        self.assertIn("body-bytes", dump)

    @patch(f"{_VIEWS}.get_url", return_value="http://srv")
    def test_003_directory_ok(self, _url) -> None:
        """directory returns JsonResponse on success"""
        cm, inst = self._cm(directory_get={"newNonce": "http://x"})
        # directory_get called twice in success path
        inst.directory_get.side_effect = [
            {"newNonce": "http://x"},
            {"newNonce": "http://x"},
        ]
        with patch(f"{_VIEWS}.Directory", return_value=cm):
            resp = self.views.directory(self._meta(self.rf.get("/directory")))
        self.assertEqual(200, resp.status_code)
        self.assertIn(b"newNonce", resp.content)

    @patch(f"{_VIEWS}.get_url", return_value="http://srv")
    def test_004_directory_error(self, _url) -> None:
        """directory returns 403 problem+json when directory_get has error"""
        cm, inst = self._cm(directory_get={"error": "denied"})
        with patch(f"{_VIEWS}.Directory", return_value=cm):
            resp = self.views.directory(self._meta(self.rf.get("/directory")))
        self.assertEqual(403, resp.status_code)
        self.assertIn(b"denied", resp.content)

    @patch(f"{_VIEWS}.logger_info")
    @patch(f"{_VIEWS}.get_url", return_value="http://srv")
    def test_005_newaccount_post(self, _url, mock_log) -> None:
        """newaccount POST builds JsonResponse with headers"""
        cm, _inst = self._cm(new=_ok({"status": "valid"}, {"Location": "/acct/1"}))
        with patch(f"{_VIEWS}.Account", return_value=cm):
            resp = self.views.newaccount(
                self._meta(
                    self.rf.post(
                        "/newaccount", data=b"{}", content_type="application/jose+json"
                    )
                )
            )
        self.assertEqual(200, resp.status_code)
        self.assertEqual("/acct/1", resp["Location"])
        self.assertTrue(mock_log.called)

    def test_006_newaccount_wrong_method(self) -> None:
        """newaccount non-POST returns ERR_RESPONSE_POST"""
        resp = self.views.newaccount(self._meta(self.rf.get("/newaccount")))
        self.assertEqual(405, resp.status_code)

    @patch(f"{_VIEWS}.logger_info")
    def test_007_newnonce_head(self, mock_log) -> None:
        """newnonce HEAD returns empty body with Replay-Nonce"""
        cm, inst = self._cm()
        inst.generate_and_add.return_value = "nonce-h"
        with patch(f"{_VIEWS}.Nonce", return_value=cm):
            resp = self.views.newnonce(self._meta(self.rf.head("/newnonce")))
        self.assertEqual(200, resp.status_code)
        self.assertEqual("nonce-h", resp["Replay-Nonce"])
        self.assertTrue(inst.expire_nonces.called)
        self.assertTrue(mock_log.called)

    @patch(f"{_VIEWS}.logger_info")
    def test_008_newnonce_get(self, mock_log) -> None:
        """newnonce GET returns 204 with Replay-Nonce"""
        cm, inst = self._cm()
        inst.generate_and_add.return_value = "nonce-g"
        with patch(f"{_VIEWS}.Nonce", return_value=cm):
            resp = self.views.newnonce(self._meta(self.rf.get("/newnonce")))
        self.assertEqual(204, resp.status_code)
        self.assertEqual("nonce-g", resp["Replay-Nonce"])
        self.assertTrue(mock_log.called)

    def test_009_newnonce_wrong_method(self) -> None:
        """newnonce POST returns ERR_RESPONSE_HEAD_GET"""
        resp = self.views.newnonce(
            self._meta(self.rf.post("/newnonce", data=b"x", content_type="text/plain"))
        )
        self.assertEqual(400, resp.status_code)

    @patch(f"{_VIEWS}.get_url", return_value="http://srv")
    def test_010_servername_get(self, _url) -> None:
        """servername_get returns escaped server name"""
        cm, _inst = self._cm(servername_get="srv.example")
        with patch(f"{_VIEWS}.Directory", return_value=cm):
            resp = self.views.servername_get(self._meta(self.rf.get("/servername_get")))
        self.assertEqual(200, resp.status_code)
        self.assertIn(b"srv.example", resp.content)

    @patch(f"{_VIEWS}.logger_info")
    @patch(f"{_VIEWS}.get_url", return_value="http://srv")
    def test_011_acct_post(self, _url, mock_log) -> None:
        """acct POST parses account and sets headers"""
        cm, _inst = self._cm(parse=_ok(header={"Replay-Nonce": "n"}))
        with patch(f"{_VIEWS}.Account", return_value=cm):
            resp = self.views.acct(
                self._meta(
                    self.rf.post(
                        "/acct", data=b"{}", content_type="application/jose+json"
                    )
                )
            )
        self.assertEqual(200, resp.status_code)
        self.assertEqual("n", resp["Replay-Nonce"])
        self.assertTrue(mock_log.called)

    @patch(f"{_VIEWS}.logger_info")
    @patch(f"{_VIEWS}.get_url", return_value="http://srv")
    def test_012_neworders_post_with_nonce(self, _url, mock_log) -> None:
        """neworders POST with Replay-Nonce in header"""
        cm, _inst = self._cm(new=_ok(header={"Replay-Nonce": "rn"}))
        with patch(f"{_VIEWS}.Order", return_value=cm):
            resp = self.views.neworders(
                self._meta(
                    self.rf.post(
                        "/neworders", data=b"{}", content_type="application/jose+json"
                    )
                )
            )
        self.assertEqual(200, resp.status_code)
        self.assertEqual("rn", resp["Replay-Nonce"])
        self.assertTrue(mock_log.called)

    @patch(f"{_VIEWS}.logger_info")
    @patch(f"{_VIEWS}.get_url", return_value="http://srv")
    def test_013_neworders_post_without_nonce(self, _url, mock_log) -> None:
        """neworders POST adds empty Replay-Nonce when missing"""
        cm, _inst = self._cm(new=_ok(header={}))
        with patch(f"{_VIEWS}.Order", return_value=cm):
            resp = self.views.neworders(
                self._meta(
                    self.rf.post(
                        "/neworders", data=b"{}", content_type="application/jose+json"
                    )
                )
            )
        self.assertEqual("", resp["Replay-Nonce"])
        self.assertTrue(mock_log.called)

    def test_014_neworders_wrong_method(self) -> None:
        """neworders GET returns ERR_RESPONSE_POST"""
        resp = self.views.neworders(self._meta(self.rf.get("/neworders")))
        self.assertEqual(405, resp.status_code)

    @patch(f"{_VIEWS}.logger_info")
    @patch(f"{_VIEWS}.get_url", return_value="http://srv")
    def test_015_authz_post(self, _url, mock_log) -> None:
        """authz POST uses new_post"""
        cm, inst = self._cm(new_post=_ok())
        with patch(f"{_VIEWS}.Authorization", return_value=cm):
            resp = self.views.authz(
                self._meta(
                    self.rf.post(
                        "/authz", data=b"{}", content_type="application/jose+json"
                    )
                )
            )
        self.assertEqual(200, resp.status_code)
        self.assertTrue(inst.new_post.called)
        self.assertFalse(inst.new_get.called)
        self.assertTrue(mock_log.called)

    @patch(f"{_VIEWS}.logger_info")
    @patch(f"{_VIEWS}.get_url", return_value="http://srv")
    def test_016_authz_get_rejected_by_default(self, _url, mock_log) -> None:
        """authz GET returns 405 when legacy_acme_get is False"""
        self.views.LEGACY_ACME_GET = False
        cm, inst = self._cm(new_get=_ok())
        with patch(f"{_VIEWS}.Authorization", return_value=cm):
            resp = self.views.authz(self._meta(self.rf.get("/authz/xyz")))
        self.assertEqual(405, resp.status_code)
        self.assertIn(b"POST-as-GET", resp.content)
        self.assertEqual("POST", resp["Allow"])
        self.assertFalse(inst.new_get.called)
        self.assertFalse(mock_log.called)

    @patch(f"{_VIEWS}.logger_info")
    @patch(f"{_VIEWS}.get_url", return_value="http://srv")
    def test_016b_authz_get_legacy_enabled(self, _url, mock_log) -> None:
        """authz GET uses new_get when legacy_acme_get is True"""
        self.views.LEGACY_ACME_GET = True
        cm, inst = self._cm(new_get=_ok())
        with patch(f"{_VIEWS}.Authorization", return_value=cm):
            resp = self.views.authz(self._meta(self.rf.get("/authz/xyz")))
        self.assertEqual(200, resp.status_code)
        self.assertTrue(inst.new_get.called)
        self.assertFalse(inst.new_post.called)
        self.assertTrue(mock_log.called)

    def test_017_authz_wrong_method(self) -> None:
        """authz HEAD returns ERR_RESPONSE_POST"""
        resp = self.views.authz(self._meta(self.rf.head("/authz")))
        self.assertEqual(405, resp.status_code)

    @patch(f"{_VIEWS}.logger_info")
    @patch(f"{_VIEWS}.get_url", return_value="http://srv")
    def test_018_chall_post(self, _url, mock_log) -> None:
        """chall POST parses challenge"""
        cm, inst = self._cm(parse=_ok())
        with patch(f"{_VIEWS}.Challenge", return_value=cm):
            resp = self.views.chall(
                self._meta(
                    self.rf.post(
                        "/chall", data=b"{}", content_type="application/jose+json"
                    )
                )
            )
        self.assertEqual(200, resp.status_code)
        self.assertTrue(inst.parse.called)
        self.assertTrue(mock_log.called)

    @patch(f"{_VIEWS}.get_url", return_value="http://srv")
    def test_019_chall_get_rejected_by_default(self, _url) -> None:
        """chall GET returns 405 when legacy_acme_get is False"""
        self.views.LEGACY_ACME_GET = False
        cm, inst = self._cm(get=_ok())
        with patch(f"{_VIEWS}.Challenge", return_value=cm):
            resp = self.views.chall(self._meta(self.rf.get("/chall/xyz")))
        self.assertEqual(405, resp.status_code)
        self.assertIn(b"POST-as-GET", resp.content)
        self.assertEqual("POST", resp["Allow"])
        self.assertFalse(inst.get.called)

    @patch(f"{_VIEWS}.get_url", return_value="http://srv")
    def test_019b_chall_get_legacy_enabled(self, _url) -> None:
        """chall GET uses challenge.get when legacy_acme_get is True"""
        self.views.LEGACY_ACME_GET = True
        cm, inst = self._cm(get=_ok())
        with patch(f"{_VIEWS}.Challenge", return_value=cm):
            resp = self.views.chall(self._meta(self.rf.get("/chall/xyz")))
        self.assertEqual(200, resp.status_code)
        self.assertTrue(inst.get.called)

    def test_020_chall_wrong_method(self) -> None:
        """chall HEAD returns ERR_RESPONSE_POST"""
        cm, _inst = self._cm()
        with patch(f"{_VIEWS}.Challenge", return_value=cm):
            resp = self.views.chall(self._meta(self.rf.head("/chall")))
        self.assertEqual(405, resp.status_code)

    @patch(f"{_VIEWS}.logger_info")
    @patch(f"{_VIEWS}.get_url", return_value="http://srv")
    def test_021_order_post(self, _url, mock_log) -> None:
        """order POST parses order"""
        cm, _inst = self._cm(parse=_ok())
        with patch(f"{_VIEWS}.Order", return_value=cm):
            resp = self.views.order(
                self._meta(
                    self.rf.post(
                        "/order", data=b"{}", content_type="application/jose+json"
                    )
                )
            )
        self.assertEqual(200, resp.status_code)
        self.assertTrue(mock_log.called)

    def test_022_order_wrong_method(self) -> None:
        """order GET returns ERR_RESPONSE_POST"""
        resp = self.views.order(self._meta(self.rf.get("/order")))
        self.assertEqual(405, resp.status_code)

    @patch(f"{_VIEWS}.logger_info")
    @patch(f"{_VIEWS}.get_url", return_value="http://srv")
    def test_023_cert_post_200(self, _url, mock_log) -> None:
        """cert POST 200 returns HttpResponse with headers"""
        cm, _inst = self._cm(
            new_post={
                "code": 200,
                "data": "PEM",
                "header": {"Content-Type": "application/pem-certificate-chain"},
            }
        )
        with patch(f"{_VIEWS}.Certificate", return_value=cm):
            resp = self.views.cert(
                self._meta(
                    self.rf.post(
                        "/cert", data=b"{}", content_type="application/jose+json"
                    )
                )
            )
        self.assertEqual(200, resp.status_code)
        self.assertEqual(b"PEM", resp.content)
        self.assertTrue(mock_log.called)

    @patch(f"{_VIEWS}.logger_info")
    @patch(f"{_VIEWS}.get_url", return_value="http://srv")
    def test_024_cert_get_error(self, _url, mock_log) -> None:
        """cert GET non-200 returns status-only HttpResponse"""
        cm, inst = self._cm(new_get={"code": 404, "data": "", "header": {}})
        with patch(f"{_VIEWS}.Certificate", return_value=cm):
            resp = self.views.cert(self._meta(self.rf.get("/cert/xyz")))
        self.assertEqual(404, resp.status_code)
        self.assertTrue(inst.new_get.called)
        self.assertTrue(mock_log.called)

    def test_025_cert_wrong_method(self) -> None:
        """cert HEAD returns ERR_RESPONSE_POST"""
        resp = self.views.cert(self._meta(self.rf.head("/cert")))
        self.assertEqual(405, resp.status_code)

    @patch(f"{_VIEWS}.logger_info")
    @patch(f"{_VIEWS}.get_url", return_value="http://srv")
    def test_026_revokecert_with_data(self, _url, mock_log) -> None:
        """revokecert POST with data → JsonResponse"""
        cm, _inst = self._cm(revoke=_ok({"status": 200}))
        with patch(f"{_VIEWS}.Certificate", return_value=cm):
            resp = self.views.revokecert(
                self._meta(
                    self.rf.post(
                        "/revokecert", data=b"{}", content_type="application/jose+json"
                    )
                )
            )
        self.assertEqual(200, resp.status_code)
        self.assertTrue(mock_log.called)

    @patch(f"{_VIEWS}.logger_info")
    @patch(f"{_VIEWS}.get_url", return_value="http://srv")
    def test_027_revokecert_without_data(self, _url, mock_log) -> None:
        """revokecert POST without data → bare HttpResponse status"""
        cm, _inst = self._cm(revoke={"code": 204, "header": {"Replay-Nonce": "r"}})
        with patch(f"{_VIEWS}.Certificate", return_value=cm):
            resp = self.views.revokecert(
                self._meta(
                    self.rf.post(
                        "/revokecert", data=b"{}", content_type="application/jose+json"
                    )
                )
            )
        self.assertEqual(204, resp.status_code)
        self.assertEqual("r", resp["Replay-Nonce"])
        self.assertTrue(mock_log.called)

    def test_028_revokecert_wrong_method(self) -> None:
        """revokecert GET returns ERR_RESPONSE_POST"""
        resp = self.views.revokecert(self._meta(self.rf.get("/revokecert")))
        self.assertEqual(405, resp.status_code)

    @patch(f"{_VIEWS}.logger_info")
    @patch(f"{_VIEWS}.get_url", return_value="http://srv")
    def test_029_trigger_with_data(self, _url, mock_log) -> None:
        """trigger POST with data → JsonResponse"""
        cm, _inst = self._cm(parse=_ok({"done": True}))
        with patch(f"{_VIEWS}.Trigger", return_value=cm):
            resp = self.views.trigger(
                self._meta(
                    self.rf.post(
                        "/trigger", data=b"{}", content_type="application/json"
                    )
                )
            )
        self.assertEqual(200, resp.status_code)
        self.assertTrue(mock_log.called)

    @patch(f"{_VIEWS}.logger_info")
    @patch(f"{_VIEWS}.get_url", return_value="http://srv")
    def test_030_trigger_without_data(self, _url, mock_log) -> None:
        """trigger POST without data → bare status"""
        cm, _inst = self._cm(parse={"code": 202, "header": {}})
        with patch(f"{_VIEWS}.Trigger", return_value=cm):
            resp = self.views.trigger(
                self._meta(
                    self.rf.post(
                        "/trigger", data=b"{}", content_type="application/json"
                    )
                )
            )
        self.assertEqual(202, resp.status_code)
        self.assertTrue(mock_log.called)

    def test_031_trigger_wrong_method(self) -> None:
        """trigger GET returns ERR_RESPONSE_POST"""
        resp = self.views.trigger(self._meta(self.rf.get("/trigger")))
        self.assertEqual(405, resp.status_code)

    @patch(f"{_VIEWS}.logger_info")
    @patch(f"{_VIEWS}.get_url", return_value="http://srv")
    def test_032_renewalinfo_get_200(self, _url, mock_log) -> None:
        """renewalinfo GET 200 → JsonResponse with headers"""
        cm, inst = self._cm(get=_ok({"suggestedWindow": {}}, {"Replay-Nonce": "ri"}))
        with patch(f"{_VIEWS}.Renewalinfo", return_value=cm):
            resp = self.views.renewalinfo(self._meta(self.rf.get("/renewal-info/x")))
        self.assertEqual(200, resp.status_code)
        self.assertEqual("ri", resp["Replay-Nonce"])
        self.assertTrue(inst.get.called)
        self.assertTrue(mock_log.called)

    @patch(f"{_VIEWS}.logger_info")
    @patch(f"{_VIEWS}.get_url", return_value="http://srv")
    def test_033_renewalinfo_post(self, _url, mock_log) -> None:
        """renewalinfo POST → bare HttpResponse status branch"""
        cm, inst = self._cm(update={"code": 204, "data": {}, "header": {}})
        with patch(f"{_VIEWS}.Renewalinfo", return_value=cm):
            resp = self.views.renewalinfo(
                self._meta(
                    self.rf.post(
                        "/renewal-info",
                        data=b"{}",
                        content_type="application/jose+json",
                    )
                )
            )
        self.assertEqual(204, resp.status_code)
        self.assertTrue(inst.update.called)
        self.assertTrue(mock_log.called)

    def test_034_renewalinfo_wrong_method(self) -> None:
        """renewalinfo HEAD returns ERR_RESPONSE_POST"""
        resp = self.views.renewalinfo(self._meta(self.rf.head("/renewal-info")))
        self.assertEqual(405, resp.status_code)

    @patch(f"{_VIEWS}.logger_info")
    def test_035_housekeeping_with_data(self, mock_log) -> None:
        """housekeeping POST with data → JsonResponse safe=False"""
        cm, _inst = self._cm(parse=_ok([{"row": 1}]))
        with patch(f"{_VIEWS}.Housekeeping", return_value=cm):
            resp = self.views.housekeeping(
                self._meta(
                    self.rf.post(
                        "/housekeeping", data=b"{}", content_type="application/json"
                    )
                )
            )
        self.assertEqual(200, resp.status_code)
        self.assertTrue(mock_log.called)

    @patch(f"{_VIEWS}.logger_info")
    def test_036_housekeeping_without_data(self, mock_log) -> None:
        """housekeeping POST without data → bare status"""
        cm, _inst = self._cm(parse={"code": 204, "header": {}})
        with patch(f"{_VIEWS}.Housekeeping", return_value=cm):
            resp = self.views.housekeeping(
                self._meta(
                    self.rf.post(
                        "/housekeeping", data=b"{}", content_type="application/json"
                    )
                )
            )
        self.assertEqual(204, resp.status_code)
        self.assertTrue(mock_log.called)

    def test_037_housekeeping_wrong_method(self) -> None:
        """housekeeping GET returns 405 JsonResponse"""
        resp = self.views.housekeeping(self._meta(self.rf.get("/housekeeping")))
        self.assertEqual(405, resp.status_code)

    @patch(f"{_VIEWS}.get_url", return_value="http://srv")
    def test_038_acmechallenge_found(self, _url) -> None:
        """acmechallenge_serve returns key authorization"""
        cm, _inst = self._cm(lookup="token.thumbprint")
        with patch(f"{_VIEWS}.Acmechallenge", return_value=cm):
            resp = self.views.acmechallenge_serve(
                self._meta(self.rf.get("/.well-known/acme-challenge/tok"))
            )
        self.assertEqual(200, resp.status_code)
        self.assertEqual(b"token.thumbprint", resp.content)

    @patch(f"{_VIEWS}.get_url", return_value="http://srv")
    def test_039_acmechallenge_not_found(self, _url) -> None:
        """acmechallenge_serve returns 404 when lookup empty"""
        cm, _inst = self._cm(lookup=None)
        with patch(f"{_VIEWS}.Acmechallenge", return_value=cm):
            resp = self.views.acmechallenge_serve(
                self._meta(self.rf.get("/.well-known/acme-challenge/tok"))
            )
        self.assertEqual(404, resp.status_code)
        self.assertIn(b"NOT FOUND", resp.content)


if __name__ == "__main__":
    unittest.main()
