#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for ms_wcce helpers"""

# pylint: disable=C0415, W0212
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestMsWcceErrors(unittest.TestCase):
    """tests for ms_wcce.errors"""

    def test_001_translate_error_code_known(self):
        """translate_error_code returns known HRESULT message"""
        from acme2certifier.cahandlers.ms_wcce.errors import translate_error_code
        from impacket import hresult_errors

        error_code = next(iter(hresult_errors.ERROR_MESSAGES))
        short, verbose = hresult_errors.ERROR_MESSAGES[error_code]
        result = translate_error_code(error_code)
        self.assertIn("code: 0x%x" % (error_code & 0xFFFFFFFF), result)
        self.assertIn(short, result)
        self.assertIn(verbose, result)

    def test_002_translate_error_code_unknown(self):
        """translate_error_code returns unknown message for unmapped codes"""
        from acme2certifier.cahandlers.ms_wcce.errors import translate_error_code

        result = translate_error_code(0xDEADBEEF)
        self.assertEqual("unknown error code: 0xdeadbeef", result)


class TestMsWcceTarget(unittest.TestCase):
    """tests for ms_wcce.target"""

    def test_001_is_ip_true(self):
        """is_ip returns True for IPv4 addresses"""
        from acme2certifier.cahandlers.ms_wcce.target import is_ip

        self.assertTrue(is_ip("127.0.0.1"))

    def test_002_is_ip_false(self):
        """is_ip returns False for hostnames"""
        from acme2certifier.cahandlers.ms_wcce.target import is_ip

        self.assertFalse(is_ip("example.com"))

    def test_003_dnsresolver_from_options_uses_ns(self):
        """DnsResolver.from_options prefers options.ns"""
        from acme2certifier.cahandlers.ms_wcce.target import DnsResolver

        options = SimpleNamespace(ns="8.8.8.8", dns_tcp=True)
        target = SimpleNamespace(dc_ip="1.1.1.1")
        resolver = DnsResolver.from_options(options, target)
        self.assertEqual(["8.8.8.8"], resolver.resolver.nameservers)
        self.assertTrue(resolver.use_tcp)

    def test_004_dnsresolver_from_options_falls_back_to_dc_ip(self):
        """DnsResolver.from_options falls back to target.dc_ip"""
        from acme2certifier.cahandlers.ms_wcce.target import DnsResolver

        options = SimpleNamespace(ns=None, dns_tcp=False)
        target = SimpleNamespace(dc_ip="9.9.9.9")
        resolver = DnsResolver.from_options(options, target)
        self.assertEqual(["9.9.9.9"], resolver.resolver.nameservers)
        self.assertFalse(resolver.use_tcp)

    def test_005_dnsresolver_create_uses_ns(self):
        """DnsResolver.create uses explicit nameserver"""
        from acme2certifier.cahandlers.ms_wcce.target import DnsResolver

        target = SimpleNamespace(dc_ip="1.1.1.1")
        resolver = DnsResolver.create(target=target, ns_="8.8.4.4", dns_tcp=True)
        self.assertEqual(["8.8.4.4"], resolver.resolver.nameservers)
        self.assertTrue(resolver.use_tcp)

    def test_006_dnsresolver_create_falls_back_to_dc_ip(self):
        """DnsResolver.create falls back to target.dc_ip"""
        from acme2certifier.cahandlers.ms_wcce.target import DnsResolver

        target = SimpleNamespace(dc_ip="1.2.3.4")
        resolver = DnsResolver.create(target=target, ns_=None, dns_tcp=False)
        self.assertEqual(["1.2.3.4"], resolver.resolver.nameservers)

    def test_007_dnsresolver_resolve_from_cache(self):
        """DnsResolver.resolve returns cached mapping"""
        from acme2certifier.cahandlers.ms_wcce.target import DnsResolver

        resolver = DnsResolver()
        resolver.mappings["host.example"] = "10.0.0.1"
        self.assertEqual("10.0.0.1", resolver.resolve("host.example"))

    def test_008_dnsresolver_resolve_ip_passthrough(self):
        """DnsResolver.resolve returns IP addresses unchanged"""
        from acme2certifier.cahandlers.ms_wcce.target import DnsResolver

        resolver = DnsResolver()
        self.assertEqual("10.0.0.2", resolver.resolve("10.0.0.2"))

    def test_009_dnsresolver_resolve_via_nameserver(self):
        """DnsResolver.resolve uses resolver answers when available"""
        from acme2certifier.cahandlers.ms_wcce.target import DnsResolver

        resolver = DnsResolver()
        resolver.resolver.nameservers = ["8.8.8.8"]
        resolver.use_tcp = False
        answer = Mock()
        answer.to_text.return_value = "10.1.2.3"
        with patch.object(resolver.resolver, "resolve", return_value=[answer]):
            self.assertEqual("10.1.2.3", resolver.resolve("host.example"))
        self.assertEqual("10.1.2.3", resolver.mappings["host.example"])

    def test_010_dnsresolver_resolve_empty_answers_then_gethostbyname(self):
        """DnsResolver.resolve falls back to gethostbyname on empty answers"""
        from acme2certifier.cahandlers.ms_wcce.target import DnsResolver

        resolver = DnsResolver()
        resolver.use_tcp = False
        mock_resolver = Mock()
        mock_resolver.nameservers = [None]
        mock_resolver.resolve.return_value = []
        resolver.resolver = mock_resolver
        with patch(
            "acme2certifier.cahandlers.ms_wcce.target.socket.gethostbyname",
            return_value="10.9.8.7",
        ):
            self.assertEqual("10.9.8.7", resolver.resolve("host.example"))
        mock_resolver.resolve.assert_called_once()

    def test_011_dnsresolver_resolve_failure_returns_hostname(self):
        """DnsResolver.resolve returns hostname when all lookups fail"""
        from acme2certifier.cahandlers.ms_wcce.target import DnsResolver

        resolver = DnsResolver()
        resolver.resolver.nameservers = ["8.8.8.8"]
        resolver.use_tcp = False
        with (
            patch.object(
                resolver.resolver, "resolve", side_effect=Exception("dns fail")
            ),
            patch(
                "acme2certifier.cahandlers.ms_wcce.target.socket.gethostbyname",
                side_effect=Exception("local fail"),
            ),
            self.assertLogs(level="WARNING") as lcm,
        ):
            self.assertEqual("host.example", resolver.resolve("host.example"))
        self.assertTrue(
            any("Failed to resolve: host.example" in msg for msg in lcm.output)
        )

    def test_012_target_init_defaults_and_warning(self):
        """Target warns on empty password and resolves remote_name"""
        from acme2certifier.cahandlers.ms_wcce.target import Target

        with patch(
            "acme2certifier.cahandlers.ms_wcce.target.DnsResolver.create"
        ) as mock_create:
            mock_resolver = Mock()
            mock_resolver.resolve.return_value = "10.0.0.5"
            mock_create.return_value = mock_resolver
            with self.assertLogs(level="WARNING") as lcm:
                target = Target(
                    domain=None,
                    username="user",
                    password="",
                    remote_name="ca.example",
                    dc_ip="1.1.1.1",
                )
        self.assertEqual("", target.domain)
        self.assertEqual("10.0.0.5", target.target_ip)
        self.assertIn(
            "Empty password supplied for user 'user'",
            " ".join(lcm.output),
        )
        self.assertIn("<Target (", repr(target))

    def test_013_target_init_remote_name_ip(self):
        """Target uses remote_name as target_ip when remote_name is an IP"""
        from acme2certifier.cahandlers.ms_wcce.target import Target

        with patch(
            "acme2certifier.cahandlers.ms_wcce.target.DnsResolver.create"
        ) as mock_create:
            mock_create.return_value = Mock()
            target = Target(
                domain="DOMAIN",
                username="user",
                password="pass",
                remote_name="192.168.1.10",
                no_pass=True,
            )
        self.assertEqual("192.168.1.10", target.target_ip)
        self.assertEqual("DOMAIN", target.domain)

    def test_014_target_repr_redacts_secrets(self):
        """Target.__repr__ redacts password, hashes, and Kerberos TGT"""
        from acme2certifier.cahandlers.ms_wcce.target import Target

        with patch(
            "acme2certifier.cahandlers.ms_wcce.target.DnsResolver.create"
        ) as mock_create:
            mock_create.return_value = Mock()
            target = Target(
                domain="DOMAIN",
                username="user",
                password="super-secret",
                remote_name="192.168.1.10",
                no_pass=True,
                tgt={"ticket": "secret-tgt"},
            )
        target.lmhash = "aabbccdd"
        target.nthash = "11223344"
        rendered = repr(target)
        self.assertIn("<Target (", rendered)
        self.assertIn("'username': 'user'", rendered)
        self.assertIn("'domain': 'DOMAIN'", rendered)
        self.assertNotIn("super-secret", rendered)
        self.assertNotIn("secret-tgt", rendered)
        self.assertNotIn("aabbccdd", rendered)
        self.assertNotIn("11223344", rendered)
        self.assertIn("'password': '******'", rendered)
        self.assertIn("'lmhash': '******'", rendered)
        self.assertIn("'nthash': '******'", rendered)
        self.assertIn("'tgt': '******'", rendered)


class TestMsWcceRpc(unittest.TestCase):
    """tests for ms_wcce.rpc"""

    def setUp(self):
        from impacket.uuid import uuidtup_to_bin

        self.interface = uuidtup_to_bin(("91ae6020-9e3c-11cf-8d7c-00aa00c091be", "0.0"))

    def _target(self):
        return SimpleNamespace(
            target_ip="10.0.0.1",
            remote_name="ca.example",
            username="user",
            password="pass",
            domain="DOMAIN",
            lmhash="",
            nthash="",
            dc_ip="10.0.0.2",
            do_kerberos=False,
        )

    @patch("acme2certifier.cahandlers.ms_wcce.rpc.transport.DCERPCTransportFactory")
    def test_001_get_dce_rpc_from_string_binding(self, mock_factory):
        """get_dce_rpc_from_string_binding configures transport and returns dce"""
        from acme2certifier.cahandlers.ms_wcce.rpc import (
            get_dce_rpc_from_string_binding,
        )
        from impacket.dcerpc.v5 import rpcrt

        mock_transport = Mock()
        mock_dce = Mock()
        mock_transport.get_dce_rpc.return_value = mock_dce
        mock_factory.return_value = mock_transport
        target = self._target()

        dce = get_dce_rpc_from_string_binding(
            "ncacn_np:10.0.0.1[\\pipe\\cert]",
            target,
            timeout=7,
            do_kerberos=True,
        )
        self.assertIs(mock_dce, dce)
        mock_transport.setRemoteHost.assert_called_once_with("10.0.0.1")
        mock_transport.setRemoteName.assert_called_once_with("ca.example")
        mock_transport.set_connect_timeout.assert_called_once_with(7)
        mock_transport.set_kerberos.assert_called_once_with(True, kdcHost="10.0.0.2")
        mock_dce.set_auth_level.assert_called_once_with(
            rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY
        )
        mock_dce.set_auth_type.assert_called_once_with(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
        self.assertTrue(target.do_kerberos)

    @patch("acme2certifier.cahandlers.ms_wcce.rpc.transport.DCERPCTransportFactory")
    def test_002_get_dce_rpc_from_string_binding_overrides(self, mock_factory):
        """get_dce_rpc_from_string_binding accepts explicit target_ip/remote_name"""
        from acme2certifier.cahandlers.ms_wcce.rpc import (
            get_dce_rpc_from_string_binding,
        )

        mock_transport = Mock()
        mock_transport.get_dce_rpc.return_value = Mock()
        mock_factory.return_value = mock_transport
        get_dce_rpc_from_string_binding(
            "binding",
            self._target(),
            target_ip="1.2.3.4",
            remote_name="override",
            do_kerberos=False,
        )
        mock_transport.setRemoteHost.assert_called_once_with("1.2.3.4")
        mock_transport.setRemoteName.assert_called_once_with("override")
        mock_transport.get_dce_rpc.return_value.set_auth_type.assert_not_called()

    @patch(
        "acme2certifier.cahandlers.ms_wcce.rpc.epm.hept_map", return_value="endpoint"
    )
    @patch("acme2certifier.cahandlers.ms_wcce.rpc.transport.DCERPCTransportFactory")
    def test_003_get_dynamic_endpoint_success(self, mock_factory, mock_hept):
        """get_dynamic_endpoint returns mapped endpoint"""
        from acme2certifier.cahandlers.ms_wcce.rpc import get_dynamic_endpoint

        mock_transport = Mock()
        mock_dce = Mock()
        mock_transport.get_dce_rpc.return_value = mock_dce
        mock_factory.return_value = mock_transport
        self.assertEqual("endpoint", get_dynamic_endpoint(self.interface, "10.0.0.1"))
        mock_dce.connect.assert_called_once_with()
        mock_hept.assert_called_once()

    @patch("acme2certifier.cahandlers.ms_wcce.rpc.transport.DCERPCTransportFactory")
    def test_004_get_dynamic_endpoint_connect_failure(self, mock_factory):
        """get_dynamic_endpoint returns None when connect fails"""
        from acme2certifier.cahandlers.ms_wcce.rpc import get_dynamic_endpoint

        mock_transport = Mock()
        mock_dce = Mock()
        mock_dce.connect.side_effect = Exception("connect fail")
        mock_transport.get_dce_rpc.return_value = mock_dce
        mock_factory.return_value = mock_transport
        with self.assertLogs(level="WARNING") as lcm:
            self.assertIsNone(get_dynamic_endpoint(self.interface, "10.0.0.1"))
        self.assertTrue(
            any("Failed to connect to endpoint mapper" in msg for msg in lcm.output)
        )

    @patch(
        "acme2certifier.cahandlers.ms_wcce.rpc.epm.hept_map",
        side_effect=Exception("map"),
    )
    @patch("acme2certifier.cahandlers.ms_wcce.rpc.transport.DCERPCTransportFactory")
    def test_005_get_dynamic_endpoint_map_failure(self, mock_factory, _mock_hept):
        """get_dynamic_endpoint returns None when hept_map fails"""
        from acme2certifier.cahandlers.ms_wcce.rpc import get_dynamic_endpoint

        mock_transport = Mock()
        mock_dce = Mock()
        mock_transport.get_dce_rpc.return_value = mock_dce
        mock_factory.return_value = mock_transport
        self.assertIsNone(get_dynamic_endpoint(self.interface, "10.0.0.1"))

    @patch("acme2certifier.cahandlers.ms_wcce.rpc.get_dce_rpc_from_string_binding")
    def test_006_get_dce_rpc_named_pipe_success(self, mock_from_binding):
        """get_dce_rpc returns dce from named pipe binding"""
        from acme2certifier.cahandlers.ms_wcce.rpc import get_dce_rpc

        mock_dce = Mock()
        mock_from_binding.return_value = mock_dce
        result = get_dce_rpc(self.interface, r"\pipe\cert", self._target())
        self.assertIs(mock_dce, result)
        mock_dce.connect.assert_called_once_with()
        mock_dce.bind.assert_called_once_with(self.interface)

    @patch(
        "acme2certifier.cahandlers.ms_wcce.rpc.get_dynamic_endpoint", return_value=None
    )
    @patch("acme2certifier.cahandlers.ms_wcce.rpc.get_dce_rpc_from_string_binding")
    def test_007_get_dce_rpc_falls_back_and_fails(self, mock_from_binding, _mock_dyn):
        """get_dce_rpc returns None when named pipe and dynamic endpoints fail"""
        from acme2certifier.cahandlers.ms_wcce.rpc import get_dce_rpc

        mock_dce = Mock()
        mock_dce.connect.side_effect = Exception("np fail")
        mock_from_binding.return_value = mock_dce
        with self.assertLogs(level="ERROR") as lcm:
            self.assertIsNone(
                get_dce_rpc(self.interface, r"\pipe\cert", self._target(), verbose=True)
            )
        self.assertTrue(
            any(
                "Failed to get dynamic TCP endpoint for CertSvc" in msg
                for msg in lcm.output
            )
        )

    @patch(
        "acme2certifier.cahandlers.ms_wcce.rpc.get_dynamic_endpoint",
        return_value="dyn-binding",
    )
    @patch("acme2certifier.cahandlers.ms_wcce.rpc.get_dce_rpc_from_string_binding")
    def test_008_get_dce_rpc_dynamic_success(self, mock_from_binding, _mock_dyn):
        """get_dce_rpc uses dynamic endpoint after named pipe failure"""
        from acme2certifier.cahandlers.ms_wcce.rpc import get_dce_rpc

        mock_np = Mock()
        mock_np.connect.side_effect = Exception("np fail")
        mock_dyn = Mock()
        mock_from_binding.side_effect = [mock_np, mock_dyn]
        result = get_dce_rpc(
            self.interface, r"\pipe\cert", self._target(), verbose=False
        )
        self.assertIs(mock_dyn, result)
        mock_dyn.connect.assert_called_once_with()
        mock_dyn.bind.assert_called_once_with(self.interface)


class TestMsWcceRequest(unittest.TestCase):
    """tests for ms_wcce.request"""

    def test_001_csr_pem_to_der(self):
        """csr_pem_to_der converts PEM CSR to DER bytes"""
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from acme2certifier.cahandlers.ms_wcce.request import csr_pem_to_der

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example")])
            )
            .sign(key, hashes.SHA256())
        )
        pem = csr.public_bytes(serialization.Encoding.PEM)
        der = csr_pem_to_der(pem)
        self.assertEqual(csr.public_bytes(serialization.Encoding.DER), der)

    def test_002_der_to_pem(self):
        """der_to_pem converts DER certificate to PEM bytes"""
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        from acme2certifier.cahandlers.ms_wcce.request import der_to_pem
        import os

        cert_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "ca", "root-ca-cert.pem"
        )
        with open(cert_path, "rb") as open_file:
            pem = open_file.read()
        cert = x509.load_pem_x509_certificate(pem)
        der = cert.public_bytes(Encoding.DER)
        self.assertEqual(pem.strip(), der_to_pem(der).strip())

    def test_003_dcerpc_session_error_str(self):
        """DCERPCSessionError.__str__ includes translated error code"""
        from acme2certifier.cahandlers.ms_wcce.request import DCERPCSessionError
        from impacket import hresult_errors

        error_code = next(iter(hresult_errors.ERROR_MESSAGES))
        err = DCERPCSessionError(error_string="err", error_code=error_code)
        text = str(err)
        self.assertTrue(text.startswith("RequestSessionError: "))
        self.assertIn("code: 0x%x" % (error_code & 0xFFFFFFFF), text)

    @patch("acme2certifier.cahandlers.ms_wcce.request.get_dce_rpc")
    def test_004_request_init(self, mock_get_dce):
        """Request.__init__ stores options and opens DCE channel"""
        from acme2certifier.cahandlers.ms_wcce.request import Request

        mock_get_dce.return_value = Mock(name="dce")
        target = SimpleNamespace(timeout=9)
        req = Request(
            target=target,
            ca="CA-NAME",
            template="WebServer",
            alt="user@example.com",
            debug=True,
            do_kerberos=True,
        )
        self.assertEqual("CA-NAME", req.ca)
        self.assertEqual("WebServer", req.template)
        self.assertEqual("user@example.com", req.alt_name)
        self.assertTrue(req.verbose)
        self.assertTrue(req.do_kerberos)
        mock_get_dce.assert_called_once()

    def _response(
        self,
        disposition=3,
        request_id=11,
        cert_bytes=b"",
        disposition_message=b"",
    ):
        return {
            "pdwDisposition": disposition,
            "pdwRequestId": request_id,
            "pctbEncodedCert": {"pb": [cert_bytes] if cert_bytes else []},
            "pctbDispositionMessage": {
                "pb": [disposition_message] if disposition_message else []
            },
        }

    @patch("acme2certifier.cahandlers.ms_wcce.request.der_to_pem", return_value=b"PEM")
    @patch(
        "acme2certifier.cahandlers.ms_wcce.request.csr_pem_to_der", return_value=b"DER"
    )
    @patch("acme2certifier.cahandlers.ms_wcce.request.get_dce_rpc")
    def test_005_get_cert_issued(self, mock_get_dce, _mock_csr, mock_der):
        """get_cert returns certificate on issued disposition"""
        from acme2certifier.cahandlers.ms_wcce.request import Request
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography import x509
        import os

        cert_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "ca", "root-ca-cert.pem"
        )
        with open(cert_path, "rb") as open_file:
            cert = x509.load_pem_x509_certificate(open_file.read())
        cert_der = cert.public_bytes(Encoding.DER)

        mock_dce = Mock()
        mock_dce.request.return_value = self._response(
            disposition=3,
            cert_bytes=cert_der,
            disposition_message="issued".encode("utf-16le"),
        )
        mock_get_dce.return_value = mock_dce
        req = Request(
            target=SimpleNamespace(timeout=5),
            ca="CA",
            template="WebServer",
            alt="alt@example.com",
        )
        with self.assertLogs(level="INFO") as lcm:
            result = req.get_cert(b"CSR")
        self.assertEqual(11, result["request_id"])
        self.assertEqual(3, result["disposition"])
        self.assertEqual("issued", result["disposition_message"])
        self.assertEqual(b"PEM", result["certificate"])
        mock_der.assert_called_once()
        self.assertTrue(
            any("Successfully requested certificate" in msg for msg in lcm.output)
        )

    @patch(
        "acme2certifier.cahandlers.ms_wcce.request.csr_pem_to_der", return_value=b"DER"
    )
    @patch("acme2certifier.cahandlers.ms_wcce.request.get_dce_rpc")
    def test_006_get_cert_issued_without_bytes(self, mock_get_dce, _mock_csr):
        """get_cert logs error when issued without certificate bytes"""
        from acme2certifier.cahandlers.ms_wcce.request import Request

        mock_dce = Mock()
        mock_dce.request.return_value = self._response(disposition=3, cert_bytes=b"")
        mock_get_dce.return_value = mock_dce
        req = Request(target=SimpleNamespace(timeout=5), ca="CA", template="T")
        with self.assertLogs(level="ERROR") as lcm:
            result = req.get_cert(b"CSR")
        self.assertIsNone(result["certificate"])
        self.assertTrue(
            any("issued but no certificate was returned" in msg for msg in lcm.output)
        )

    @patch(
        "acme2certifier.cahandlers.ms_wcce.request.csr_pem_to_der", return_value=b"DER"
    )
    @patch("acme2certifier.cahandlers.ms_wcce.request.get_dce_rpc")
    def test_007_get_cert_pending(self, mock_get_dce, _mock_csr):
        """get_cert logs warning for pending disposition"""
        from acme2certifier.cahandlers.ms_wcce.request import Request

        mock_dce = Mock()
        mock_dce.request.return_value = self._response(disposition=5)
        mock_get_dce.return_value = mock_dce
        req = Request(target=SimpleNamespace(timeout=5), ca="CA", template="T")
        with self.assertLogs(level="WARNING") as lcm:
            result = req.get_cert(b"CSR")
        self.assertEqual(5, result["disposition"])
        self.assertTrue(any("pending approval" in msg for msg in lcm.output))

    @patch("acme2certifier.cahandlers.ms_wcce.request.translate_error_code")
    @patch(
        "acme2certifier.cahandlers.ms_wcce.request.csr_pem_to_der", return_value=b"DER"
    )
    @patch("acme2certifier.cahandlers.ms_wcce.request.get_dce_rpc")
    def test_008_get_cert_known_error(self, mock_get_dce, _mock_csr, mock_translate):
        """get_cert logs known error codes"""
        from acme2certifier.cahandlers.ms_wcce.request import Request

        mock_translate.return_value = "code: 0x1 - KNOWN - detail"
        mock_dce = Mock()
        mock_dce.request.return_value = self._response(disposition=1)
        mock_get_dce.return_value = mock_dce
        req = Request(target=SimpleNamespace(timeout=5), ca="CA", template="T")
        with self.assertLogs(level="ERROR") as lcm:
            req.get_cert(b"CSR")
        self.assertTrue(
            any(
                "Got error while trying to request certificate" in msg
                for msg in lcm.output
            )
        )

    @patch("acme2certifier.cahandlers.ms_wcce.request.translate_error_code")
    @patch(
        "acme2certifier.cahandlers.ms_wcce.request.csr_pem_to_der", return_value=b"DER"
    )
    @patch("acme2certifier.cahandlers.ms_wcce.request.get_dce_rpc")
    def test_009_get_cert_unknown_error(self, mock_get_dce, _mock_csr, mock_translate):
        """get_cert logs unknown error codes with disposition message"""
        from acme2certifier.cahandlers.ms_wcce.request import Request

        mock_translate.return_value = "unknown error code: 0x99"
        mock_dce = Mock()
        mock_dce.request.return_value = self._response(
            disposition=0x99,
            disposition_message=b"a",  # odd length -> utf-16le decode failure
        )
        mock_get_dce.return_value = mock_dce
        req = Request(target=SimpleNamespace(timeout=5), ca="CA", template="T")
        with self.assertLogs(level="ERROR") as lcm:
            result = req.get_cert(b"CSR")
        self.assertIsNone(result["disposition_message"])
        self.assertTrue(
            any(
                "Got unknown error while trying to request certificate" in msg
                for msg in lcm.output
            )
        )


if __name__ == "__main__":

    unittest.main()
