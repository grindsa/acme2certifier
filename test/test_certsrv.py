#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for certsrv"""

# pylint: disable=C0415, R0904, W0212
import sys
import types
import unittest
import warnings
from unittest.mock import patch, Mock, MagicMock, call

sys.path.insert(0, ".")
sys.path.insert(1, "..")


def _fake_requests_gssapi(auth_cls):
    """Build a fake requests_gssapi module exposing HTTPSPNEGOAuth."""
    fake_mod = types.ModuleType("requests_gssapi")
    fake_mod.HTTPSPNEGOAuth = auth_cls
    return fake_mod


class TestCertsrv(unittest.TestCase):
    """test class for acme2certifier.cahandlers.certsrv"""

    def setUp(self):
        """setup unittest"""
        import logging
        from acme2certifier.cahandlers import certsrv as certsrv_mod

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self.mod = certsrv_mod

    def tearDown(self):
        """teardown"""
        pass

    def _make_certsrv(self, **kwargs):
        """create Certsrv with mocked Session"""
        defaults = {
            "server": "ca.example.com",
            "url": "https://ca.example.com/certsrv",
            "username": "user",
            "password": "pass",
            "auth_method": "basic",
            "verify": False,
        }
        defaults.update(kwargs)
        with patch("acme2certifier.cahandlers.certsrv.requests.Session") as mock_sess:
            session = MagicMock()
            mock_sess.return_value = session
            obj = self.mod.Certsrv(**defaults)
            obj.session = session
            return obj

    def test_001_request_denied_exception(self):
        """RequestDeniedException stores message and response"""
        exc = self.mod.RequestDeniedException("denied", "html-body")
        self.assertEqual(str(exc), "denied")
        self.assertEqual(exc.response, "html-body")

    def test_002_could_not_retrieve_exception(self):
        """CouldNotRetrieveCertificateException stores message and response"""
        exc = self.mod.CouldNotRetrieveCertificateException("fail", b"raw")
        self.assertEqual(str(exc), "fail")
        self.assertEqual(exc.response, b"raw")

    def test_003_certificate_pending_exception(self):
        """CertificatePendingException builds message and stores req_id"""
        exc = self.mod.CertificatePendingException("42")
        self.assertEqual(exc.req_id, "42")
        self.assertIn("Your Request Id is 42.", str(exc))
        self.assertIn("administrator to issue", str(exc))

    @patch("acme2certifier.cahandlers.certsrv.requests.Session")
    def test_004_init_verify_false(self, mock_sess):
        """Certsrv __init__ with verify=False"""
        session = MagicMock()
        mock_sess.return_value = session
        obj = self.mod.Certsrv(
            "ca.example.com",
            "https://ca.example.com/certsrv",
            "user",
            "pass",
            verify=False,
        )
        self.assertFalse(session.verify)
        self.assertEqual(obj.server, "ca.example.com")
        self.assertEqual(obj.url, "https://ca.example.com/certsrv")
        self.assertEqual(obj.auth_method, "basic")
        self.assertEqual(session.auth, ("user", "pass"))
        self.assertIn("User-agent", session.headers)

    @patch("acme2certifier.cahandlers.certsrv.requests.Session")
    def test_005_init_cafile(self, mock_sess):
        """Certsrv __init__ with cafile sets session.verify"""
        session = MagicMock()
        mock_sess.return_value = session
        obj = self.mod.Certsrv(
            "ca.example.com",
            None,
            "user",
            "pass",
            cafile="/path/to/ca.pem",
            verify=True,
        )
        self.assertEqual(session.verify, "/path/to/ca.pem")
        self.assertIsNone(obj.url)

    @patch("acme2certifier.cahandlers.certsrv._get_ca_bundle")
    @patch("acme2certifier.cahandlers.certsrv.requests.Session")
    def test_006_init_default_ca_bundle(self, mock_sess, mock_bundle):
        """Certsrv __init__ uses _get_ca_bundle when verify and no cafile"""
        session = MagicMock()
        mock_sess.return_value = session
        mock_bundle.return_value = "/etc/ssl/certs/ca-certificates.crt"
        obj = self.mod.Certsrv(
            "ca.example.com",
            None,
            "user",
            "pass",
            verify=True,
            timeout=10,
            proxies={"http": "http://proxy"},
        )
        mock_bundle.assert_called_once_with()
        self.assertEqual(session.verify, "/etc/ssl/certs/ca-certificates.crt")
        self.assertEqual(obj.timeout, 10)
        self.assertEqual(obj.proxies, {"http": "http://proxy"})

    def test_007_set_credentials_basic(self):
        """_set_credentials basic auth"""
        obj = self._make_certsrv(auth_method="basic")
        obj._set_credentials("u", "p")
        self.assertEqual(obj.session.auth, ("u", "p"))

    @patch.dict("sys.modules", {"requests_ntlm": MagicMock()})
    def test_008_set_credentials_ntlm(self):
        """_set_credentials ntlm auth (stub package; do not require requests_ntlm installed)"""
        mock_ntlm = sys.modules["requests_ntlm"]
        mock_ntlm.HttpNtlmAuth.return_value = "ntlm-auth"
        obj = self._make_certsrv(auth_method="basic")
        obj.auth_method = "ntlm"
        mock_ntlm.HttpNtlmAuth.reset_mock()
        obj._set_credentials("DOMAIN\\user", "pass")
        mock_ntlm.HttpNtlmAuth.assert_called_once_with("DOMAIN\\user", "pass")
        self.assertEqual(obj.session.auth, "ntlm-auth")

    def test_009_set_credentials_cert(self):
        """_set_credentials cert auth"""
        obj = self._make_certsrv(auth_method="basic")
        obj.auth_method = "cert"
        obj._set_credentials("/path/cert.pem", "/path/key.pem")
        self.assertEqual(obj.session.cert, ("/path/cert.pem", "/path/key.pem"))

    @patch.dict("sys.modules", {"requests_gssapi": MagicMock(), "gssapi": MagicMock()})
    def test_010_set_credentials_gssapi_with_password(self):
        """_set_credentials gssapi with username/password"""
        mock_gssapi = sys.modules["gssapi"]
        mock_requests_gssapi = sys.modules["requests_gssapi"]
        mock_cred = MagicMock()
        mock_cred.creds = "creds"
        mock_gssapi.raw.acquire_cred_with_password.return_value = mock_cred
        mock_gssapi.Name.return_value = "name"
        mock_gssapi.OID.from_int_seq.return_value = "oid"
        mock_requests_gssapi.HTTPSPNEGOAuth.return_value = "spnego"

        obj = self._make_certsrv(auth_method="basic")
        obj.auth_method = "gssapi"
        mock_gssapi.raw.acquire_cred_with_password.reset_mock()
        mock_requests_gssapi.HTTPSPNEGOAuth.reset_mock()
        obj._set_credentials("user", "secret")
        mock_gssapi.raw.acquire_cred_with_password.assert_called_once()
        mock_requests_gssapi.HTTPSPNEGOAuth.assert_called_once_with(
            creds="creds", mech="oid"
        )
        self.assertEqual(obj.session.auth, "spnego")

    @patch.dict("sys.modules", {"requests_gssapi": MagicMock(), "gssapi": MagicMock()})
    def test_011_set_credentials_gssapi_without_password(self):
        """_set_credentials gssapi with default credential cache"""
        mock_requests_gssapi = sys.modules["requests_gssapi"]
        mock_requests_gssapi.HTTPSPNEGOAuth.return_value = "spnego-default"

        obj = self._make_certsrv(auth_method="basic")
        obj.auth_method = "gssapi"
        mock_requests_gssapi.HTTPSPNEGOAuth.reset_mock()
        obj._set_credentials("user", None)
        mock_requests_gssapi.HTTPSPNEGOAuth.assert_called_once_with()
        self.assertEqual(obj.session.auth, "spnego-default")

    def test_012_post(self):
        """_post delegates to session.post and _handle_response"""
        obj = self._make_certsrv()
        mock_resp = MagicMock()
        obj.session.post.return_value = mock_resp
        with patch.object(obj, "_handle_response", return_value=mock_resp) as mock_h:
            result = obj._post("https://example/url", data={"a": 1})
        obj.session.post.assert_called_once_with(
            "https://example/url",
            timeout=obj.timeout,
            proxies=obj.proxies,
            data={"a": 1},
        )
        mock_h.assert_called_once_with(mock_resp)
        self.assertIs(result, mock_resp)

    def test_013_get(self):
        """_get delegates to session.get and _handle_response"""
        obj = self._make_certsrv()
        mock_resp = MagicMock()
        obj.session.get.return_value = mock_resp
        with patch.object(obj, "_handle_response", return_value=mock_resp) as mock_h:
            result = obj._get("https://example/url", params={"x": 1})
        obj.session.get.assert_called_once_with(
            "https://example/url",
            timeout=obj.timeout,
            proxies=obj.proxies,
            params={"x": 1},
        )
        mock_h.assert_called_once_with(mock_resp)
        self.assertIs(result, mock_resp)

    def test_014_handle_response_text(self):
        """_handle_response with decodable content"""
        response = MagicMock()
        response.request.method = "GET"
        response.request.url = "https://example"
        response.request.headers = {"A": "1"}
        response.request.body = None
        response.content = b"hello"
        response.status_code = 200
        response.headers = {"Content-Type": "text/html"}
        result = self.mod.Certsrv._handle_response(response)
        response.raise_for_status.assert_called_once_with()
        self.assertIs(result, response)

    def test_015_handle_response_binary(self):
        """_handle_response with UnicodeDecodeError uses base64"""
        response = MagicMock()
        response.request.method = "GET"
        response.request.url = "https://example"
        response.request.headers = {"A": "1"}
        response.request.body = b"\xff"
        response.content = b"\xff\xfe\x00"
        response.status_code = 200
        response.headers = {"Content-Type": "application/octet-stream"}
        result = self.mod.Certsrv._handle_response(response)
        response.raise_for_status.assert_called_once_with()
        self.assertIs(result, response)

    def test_016_get_cert_with_url_and_attributes(self):
        """get_cert with url and attributes success path"""
        obj = self._make_certsrv()
        post_resp = MagicMock()
        post_resp.text = '<a href="certnew.cer?ReqID=99&amp;Enc=b64">cert</a>'
        with patch.object(obj, "_post", return_value=post_resp) as mock_post:
            with patch.object(
                obj, "get_existing_cert", return_value=b"CERT"
            ) as mock_ex:
                result = obj.get_cert("CSRDATA", "WebServer", attributes="Attr:1\r\n")
        self.assertEqual(result, b"CERT")
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://ca.example.com/certsrv/certfnsh.asp")
        self.assertIn("CertificateTemplate:WebServer", kwargs["data"]["CertAttrib"])
        self.assertIn("Attr:1", kwargs["data"]["CertAttrib"])
        mock_ex.assert_called_once_with("99", "b64")

    def test_017_get_cert_with_server_no_url(self):
        """get_cert builds server URL when url is empty"""
        obj = self._make_certsrv(url="")
        post_resp = MagicMock()
        post_resp.text = "certnew.cer?ReqID=7&"
        with patch.object(obj, "_post", return_value=post_resp) as mock_post:
            with patch.object(obj, "get_existing_cert", return_value=b"C"):
                obj.get_cert("CSR", "Tpl")
        self.assertEqual(
            mock_post.call_args[0][0], "https://ca.example.com/certsrv/certfnsh.asp"
        )

    def test_018_get_cert_pending(self):
        """get_cert raises CertificatePendingException"""
        obj = self._make_certsrv()
        post_resp = MagicMock()
        post_resp.text = "Certificate Pending<br>Your Request Id is 123."
        with patch.object(obj, "_post", return_value=post_resp):
            with self.assertRaises(self.mod.CertificatePendingException) as cm:
                obj.get_cert("CSR", "Tpl")
        self.assertEqual(cm.exception.req_id, "123")

    def test_019_get_cert_denied_with_disposition(self):
        """get_cert raises RequestDeniedException with disposition message"""
        obj = self._make_certsrv()
        post_resp = MagicMock()
        post_resp.text = 'The disposition message is "Denied by policy"'
        with patch.object(obj, "_post", return_value=post_resp):
            with self.assertRaises(self.mod.RequestDeniedException) as cm:
                obj.get_cert("CSR", "Tpl")
        self.assertEqual(str(cm.exception), "Denied by policy")
        self.assertEqual(cm.exception.response, post_resp.text)

    def test_020_get_cert_denied_unknown(self):
        """get_cert raises RequestDeniedException with unknown message"""
        obj = self._make_certsrv()
        post_resp = MagicMock()
        post_resp.text = "Something failed without useful message"
        with patch.object(obj, "_post", return_value=post_resp):
            with self.assertRaises(self.mod.RequestDeniedException) as cm:
                obj.get_cert("CSR", "Tpl")
        self.assertEqual(str(cm.exception), self.mod.UNKOWN_ERR_MSG)

    def test_021_get_existing_cert_success_url(self):
        """get_existing_cert success with url"""
        obj = self._make_certsrv()
        resp = MagicMock()
        resp.headers = {"Content-Type": "application/pkix-cert"}
        resp.content = b"CERTBYTES"
        with patch.object(obj, "_get", return_value=resp) as mock_get:
            result = obj.get_existing_cert("10", encoding="bin")
        self.assertEqual(result, b"CERTBYTES")
        mock_get.assert_called_once_with(
            "https://ca.example.com/certsrv/certnew.cer",
            params={"ReqID": "10", "Enc": "bin"},
        )

    def test_022_get_existing_cert_success_server(self):
        """get_existing_cert success with server path"""
        obj = self._make_certsrv(url=None)
        resp = MagicMock()
        resp.headers = {"Content-Type": "application/pkix-cert"}
        resp.content = b"C"
        with patch.object(obj, "_get", return_value=resp) as mock_get:
            result = obj.get_existing_cert("1")
        self.assertEqual(result, b"C")
        self.assertEqual(
            mock_get.call_args[0][0], "https://ca.example.com/certsrv/certnew.cer"
        )

    def test_023_get_existing_cert_error_disposition(self):
        """get_existing_cert error with disposition message"""
        obj = self._make_certsrv()
        resp = MagicMock()
        resp.headers = {"Content-Type": "text/html"}
        resp.text = "Disposition message: Denied\t\tTaken Offline\r\n"
        with patch.object(obj, "_get", return_value=resp):
            with self.assertRaises(self.mod.CouldNotRetrieveCertificateException) as cm:
                obj.get_existing_cert("1")
        self.assertEqual(str(cm.exception), "Taken Offline")

    def test_024_get_existing_cert_error_unknown(self):
        """get_existing_cert error unknown message"""
        obj = self._make_certsrv()
        resp = MagicMock()
        resp.headers = {"Content-Type": "text/html"}
        resp.text = "no disposition here"
        with patch.object(obj, "_get", return_value=resp):
            with self.assertRaises(self.mod.CouldNotRetrieveCertificateException) as cm:
                obj.get_existing_cert("1")
        self.assertEqual(str(cm.exception), self.mod.UNKOWN_ERR_MSG)

    def test_025_get_ca_cert_success_url(self):
        """get_ca_cert success with url"""
        obj = self._make_certsrv()
        page = MagicMock()
        page.text = "var nRenewals=3;"
        cert = MagicMock()
        cert.headers = {"Content-Type": "application/pkix-cert"}
        cert.content = b"CACERT"
        with patch.object(obj, "_get", side_effect=[page, cert]) as mock_get:
            result = obj.get_ca_cert(encoding="b64")
        self.assertEqual(result, b"CACERT")
        self.assertEqual(
            mock_get.call_args_list[0][0][0],
            "https://ca.example.com/certsrv/certcarc.asp",
        )
        self.assertEqual(
            mock_get.call_args_list[1],
            call(
                "https://ca.example.com/certsrv/certnew.cer",
                params={"ReqID": "CACert", "Enc": "b64", "Renewal": "3"},
            ),
        )

    def test_026_get_ca_cert_success_server(self):
        """get_ca_cert success with server path"""
        obj = self._make_certsrv(url="")
        page = MagicMock()
        page.text = "var nRenewals=0;"
        cert = MagicMock()
        cert.headers = {"Content-Type": "application/pkix-cert"}
        cert.content = b"CA"
        with patch.object(obj, "_get", side_effect=[page, cert]) as mock_get:
            result = obj.get_ca_cert()
        self.assertEqual(result, b"CA")
        self.assertEqual(
            mock_get.call_args_list[0][0][0],
            "https://ca.example.com/certsrv/certcarc.asp",
        )
        self.assertEqual(
            mock_get.call_args_list[1][0][0],
            "https://ca.example.com/certsrv/certnew.cer",
        )

    def test_027_get_ca_cert_wrong_content_type(self):
        """get_ca_cert raises on wrong content type"""
        obj = self._make_certsrv()
        page = MagicMock()
        page.text = "var nRenewals=1;"
        cert = MagicMock()
        cert.headers = {"Content-Type": "text/html"}
        cert.content = b"err"
        with patch.object(obj, "_get", side_effect=[page, cert]):
            with self.assertRaises(self.mod.CouldNotRetrieveCertificateException) as cm:
                obj.get_ca_cert()
        self.assertEqual(str(cm.exception), self.mod.UNKOWN_ERR_MSG)
        self.assertEqual(cm.exception.response, b"err")

    def test_028_get_chain_success_url(self):
        """get_chain success with url"""
        obj = self._make_certsrv()
        page = MagicMock()
        page.text = "var nRenewals=2;"
        chain = MagicMock()
        chain.headers = {"Content-Type": "application/x-pkcs7-certificates"}
        chain.content = b"CHAIN"
        with patch.object(obj, "_get", side_effect=[page, chain]) as mock_get:
            result = obj.get_chain(encoding="bin")
        self.assertEqual(result, b"CHAIN")
        self.assertEqual(
            mock_get.call_args_list[0][0][0],
            "https://ca.example.com/certsrv/certcarc.asp",
        )
        self.assertEqual(
            mock_get.call_args_list[1],
            call(
                "https://ca.example.com/certsrv/certnew.p7b",
                params={"ReqID": "CACert", "Renewal": "2", "Enc": "bin"},
            ),
        )

    def test_029_get_chain_success_server(self):
        """get_chain success with server path"""
        obj = self._make_certsrv(url=None)
        page = MagicMock()
        page.text = "var nRenewals=1;"
        chain = MagicMock()
        chain.headers = {"Content-Type": "application/x-pkcs7-certificates"}
        chain.content = b"P7"
        with patch.object(obj, "_get", side_effect=[page, chain]) as mock_get:
            result = obj.get_chain()
        self.assertEqual(result, b"P7")
        self.assertEqual(
            mock_get.call_args_list[0][0][0],
            "https://ca.example.com/certsrv/certcarc.asp",
        )
        self.assertEqual(
            mock_get.call_args_list[1][0][0],
            "https://ca.example.com/certsrv/certnew.p7b",
        )

    def test_030_get_chain_wrong_content_type(self):
        """get_chain raises on wrong content type"""
        obj = self._make_certsrv()
        page = MagicMock()
        page.text = "var nRenewals=0;"
        chain = MagicMock()
        chain.headers = {"Content-Type": "text/html"}
        chain.content = b"bad"
        with patch.object(obj, "_get", side_effect=[page, chain]):
            with self.assertRaises(self.mod.CouldNotRetrieveCertificateException) as cm:
                obj.get_chain()
        self.assertEqual(str(cm.exception), self.mod.UNKOWN_ERR_MSG)
        self.assertEqual(cm.exception.response, b"bad")

    def test_031_check_credentials_success_url(self):
        """check_credentials success with url"""
        obj = self._make_certsrv()
        with patch.object(obj, "_get", return_value=MagicMock()) as mock_get:
            self.assertTrue(obj.check_credentials())
        mock_get.assert_called_once_with("https://ca.example.com/certsrv")

    def test_032_check_credentials_success_server(self):
        """check_credentials success with server path"""
        obj = self._make_certsrv(url="")
        with patch.object(obj, "_get", return_value=MagicMock()) as mock_get:
            self.assertTrue(obj.check_credentials())
        mock_get.assert_called_once_with("https://ca.example.com/certsrv/")

    def test_033_check_credentials_401(self):
        """check_credentials returns False on 401"""
        import requests

        obj = self._make_certsrv()
        http_err = requests.exceptions.HTTPError()
        http_err.response = MagicMock(status_code=401)
        with patch.object(obj, "_get", side_effect=http_err):
            self.assertFalse(obj.check_credentials())

    def test_034_check_credentials_other_http_error(self):
        """check_credentials re-raises non-401 HTTPError"""
        import requests

        obj = self._make_certsrv()
        http_err = requests.exceptions.HTTPError()
        http_err.response = MagicMock(status_code=500)
        with patch.object(obj, "_get", side_effect=http_err):
            with self.assertRaises(requests.exceptions.HTTPError):
                obj.check_credentials()

    def test_035_update_credentials_ntlm(self):
        """update_credentials closes session for ntlm"""
        obj = self._make_certsrv(auth_method="basic")
        obj.auth_method = "ntlm"
        with patch.object(obj, "_set_credentials") as mock_set:
            obj.update_credentials("u2", "p2")
        obj.session.close.assert_called_once_with()
        mock_set.assert_called_once_with("u2", "p2")

    def test_036_update_credentials_cert(self):
        """update_credentials closes session for cert"""
        obj = self._make_certsrv(auth_method="basic")
        obj.auth_method = "cert"
        with patch.object(obj, "_set_credentials") as mock_set:
            obj.update_credentials("/c", "/k")
        obj.session.close.assert_called_once_with()
        mock_set.assert_called_once_with("/c", "/k")

    def test_037_update_credentials_gssapi(self):
        """update_credentials closes session for gssapi"""
        obj = self._make_certsrv(auth_method="basic")
        obj.auth_method = "gssapi"
        with patch.object(obj, "_set_credentials") as mock_set:
            obj.update_credentials("u", "p")
        obj.session.close.assert_called_once_with()
        mock_set.assert_called_once_with("u", "p")

    def test_038_update_credentials_basic(self):
        """update_credentials basic does not close session"""
        obj = self._make_certsrv(auth_method="basic")
        with patch.object(obj, "_set_credentials") as mock_set:
            obj.update_credentials("u", "p")
        obj.session.close.assert_not_called()
        mock_set.assert_called_once_with("u", "p")

    @patch("acme2certifier.cahandlers.certsrv.os.path.isfile")
    def test_039_get_ca_bundle_found(self, mock_isfile):
        """_get_ca_bundle returns first existing path"""

        def _isfile(path):
            return path == "/etc/ssl/ca-bundle.pem"

        mock_isfile.side_effect = _isfile
        self.assertEqual(self.mod._get_ca_bundle(), "/etc/ssl/ca-bundle.pem")

    @patch("acme2certifier.cahandlers.certsrv.os.path.isfile", return_value=False)
    def test_040_get_ca_bundle_fallback(self, mock_isfile):
        """_get_ca_bundle returns True when no bundle found"""
        self.assertTrue(self.mod._get_ca_bundle())
        self.assertEqual(mock_isfile.call_count, 5)

    @patch("acme2certifier.cahandlers.certsrv.Certsrv")
    def test_041_deprecated_get_cert(self, mock_cls):
        """deprecated get_cert warns and delegates"""
        instance = MagicMock()
        instance.get_cert.return_value = b"C"
        mock_cls.return_value = instance
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = self.mod.get_cert("srv", "csr", "tpl", "u", "p", encoding="bin")
        self.assertEqual(result, b"C")
        self.assertTrue(any(issubclass(w.category, DeprecationWarning) for w in caught))
        mock_cls.assert_called_once_with("srv", "u", "p")
        instance.get_cert.assert_called_once_with("csr", "tpl", "bin")

    @patch("acme2certifier.cahandlers.certsrv.Certsrv")
    def test_042_deprecated_get_existing_cert(self, mock_cls):
        """deprecated get_existing_cert warns and delegates"""
        instance = MagicMock()
        instance.get_existing_cert.return_value = b"E"
        mock_cls.return_value = instance
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = self.mod.get_existing_cert("srv", "9", "u", "p")
        self.assertEqual(result, b"E")
        self.assertTrue(any(issubclass(w.category, DeprecationWarning) for w in caught))
        mock_cls.assert_called_once_with("srv", "u", "p")
        instance.get_existing_cert.assert_called_once_with("9", "b64")

    @patch("acme2certifier.cahandlers.certsrv.Certsrv")
    def test_043_deprecated_get_ca_cert(self, mock_cls):
        """deprecated get_ca_cert warns and delegates"""
        instance = MagicMock()
        instance.get_ca_cert.return_value = b"CA"
        mock_cls.return_value = instance
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = self.mod.get_ca_cert("srv", "u", "p", encoding="bin")
        self.assertEqual(result, b"CA")
        self.assertTrue(any(issubclass(w.category, DeprecationWarning) for w in caught))
        instance.get_ca_cert.assert_called_once_with("bin")

    @patch("acme2certifier.cahandlers.certsrv.Certsrv")
    def test_044_deprecated_get_chain(self, mock_cls):
        """deprecated get_chain warns and delegates"""
        instance = MagicMock()
        instance.get_chain.return_value = b"CH"
        mock_cls.return_value = instance
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = self.mod.get_chain("srv", "u", "p")
        self.assertEqual(result, b"CH")
        self.assertTrue(any(issubclass(w.category, DeprecationWarning) for w in caught))
        instance.get_chain.assert_called_once_with("bin")

    @patch("acme2certifier.cahandlers.certsrv.Certsrv")
    def test_045_deprecated_check_credentials(self, mock_cls):
        """deprecated check_credentials warns and delegates"""
        instance = MagicMock()
        instance.check_credentials.return_value = True
        mock_cls.return_value = instance
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = self.mod.check_credentials("srv", "u", "p", auth_method="ntlm")
        self.assertTrue(result)
        self.assertTrue(any(issubclass(w.category, DeprecationWarning) for w in caught))
        mock_cls.assert_called_once_with("srv", "u", "p", auth_method="ntlm")
        instance.check_credentials.assert_called_once_with()

    def test_046_gssapi_channel_bindings_supported_true(self):
        """gssapi_channel_bindings_supported returns True when parameter exists"""

        class FakeAuth:
            def __init__(self, channel_bindings=None, **_kwargs):
                self.channel_bindings = channel_bindings

        with patch.dict(
            "sys.modules", {"requests_gssapi": _fake_requests_gssapi(FakeAuth)}
        ):
            self.assertTrue(self.mod.gssapi_channel_bindings_supported())

    def test_047_gssapi_channel_bindings_supported_false_missing_param(self):
        """gssapi_channel_bindings_supported returns False without parameter"""

        class FakeAuth:
            def __init__(self, **_kwargs):
                pass

        with patch.dict(
            "sys.modules", {"requests_gssapi": _fake_requests_gssapi(FakeAuth)}
        ):
            self.assertFalse(self.mod.gssapi_channel_bindings_supported())

    def test_048_gssapi_channel_bindings_supported_false_import_error(self):
        """gssapi_channel_bindings_supported returns False if import fails"""
        import builtins

        real_import = builtins.__import__

        def _fake_import(name, *args, **kwargs):
            if name == "requests_gssapi":
                raise ImportError("missing")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=_fake_import):
            self.assertFalse(self.mod.gssapi_channel_bindings_supported())

    def test_049_http_spnego_auth_without_bindings(self):
        """_http_spnego_auth omits channel_bindings when unset"""
        calls = []

        class FakeAuth:
            def __init__(self, **kwargs):
                calls.append(kwargs)

        with patch.dict(
            "sys.modules", {"requests_gssapi": _fake_requests_gssapi(FakeAuth)}
        ):
            client = self.mod.Certsrv.__new__(self.mod.Certsrv)
            client.channel_bindings = None
            auth = client._http_spnego_auth(creds="cred")
            self.assertIsInstance(auth, FakeAuth)
            self.assertEqual([{"creds": "cred"}], calls)

    def test_050_http_spnego_auth_with_bindings(self):
        """_http_spnego_auth passes channel_bindings when supported"""
        calls = []

        class FakeAuth:
            def __init__(self, channel_bindings=None, **kwargs):
                calls.append({"channel_bindings": channel_bindings, **kwargs})

        with patch.dict(
            "sys.modules", {"requests_gssapi": _fake_requests_gssapi(FakeAuth)}
        ):
            with patch(
                "acme2certifier.cahandlers.certsrv.gssapi_channel_bindings_supported",
                return_value=True,
            ):
                client = self.mod.Certsrv.__new__(self.mod.Certsrv)
                client.channel_bindings = "tls-server-end-point"
                client._http_spnego_auth()
                self.assertEqual(
                    [{"channel_bindings": "tls-server-end-point"}], calls
                )

    def test_051_http_spnego_auth_unsupported_raises(self):
        """_http_spnego_auth raises when bindings requested but unsupported"""

        class FakeAuth:
            def __init__(self, **_kwargs):
                pass

        with patch.dict(
            "sys.modules", {"requests_gssapi": _fake_requests_gssapi(FakeAuth)}
        ):
            with patch(
                "acme2certifier.cahandlers.certsrv.gssapi_channel_bindings_supported",
                return_value=False,
            ):
                client = self.mod.Certsrv.__new__(self.mod.Certsrv)
                client.channel_bindings = "tls-server-end-point"
                with self.assertRaises(RuntimeError):
                    client._http_spnego_auth()

    def test_052_http_spnego_auth_invalid_value(self):
        """_http_spnego_auth rejects unsupported channel_bindings values"""

        class FakeAuth:
            def __init__(self, **_kwargs):
                pass

        with patch.dict(
            "sys.modules", {"requests_gssapi": _fake_requests_gssapi(FakeAuth)}
        ):
            client = self.mod.Certsrv.__new__(self.mod.Certsrv)
            client.channel_bindings = "invalid"
            with self.assertRaises(ValueError):
                client._http_spnego_auth()


    @patch.dict("sys.modules", {"requests_gssapi": MagicMock(), "gssapi": MagicMock()})
    def test_053_set_credentials_gssapi_with_explicit_creds(self):
        """_set_credentials gssapi prefers explicit gssapi_creds over default cache"""
        mock_requests_gssapi = sys.modules["requests_gssapi"]
        mock_requests_gssapi.HTTPSPNEGOAuth.return_value = "spnego-explicit"
        explicit = MagicMock()
        explicit.creds = "raw-creds"

        obj = self._make_certsrv(auth_method="basic")
        obj.auth_method = "gssapi"
        obj.gssapi_creds = explicit
        mock_requests_gssapi.HTTPSPNEGOAuth.reset_mock()
        obj._set_credentials("user", None)
        mock_requests_gssapi.HTTPSPNEGOAuth.assert_called_once_with(creds="raw-creds")
        self.assertEqual(obj.session.auth, "spnego-explicit")


if __name__ == "__main__":
    unittest.main()
