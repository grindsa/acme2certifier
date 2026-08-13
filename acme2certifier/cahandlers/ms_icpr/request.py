"""request.py"""

# pylint: disable=C0209, C0415, E0401, R0913, W1201
import logging
from typing import Any, Dict, Optional, Tuple
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization.pkcs7 import (
    load_der_pkcs7_certificates,
)
from impacket.dcerpc.v5 import rpcrt
from impacket.dcerpc.v5.dtypes import DWORD, LPWSTR, PBYTE, ULONG
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.nrpc import checkNullString
from impacket.uuid import uuidtup_to_bin

from acme2certifier.cahandlers.ms_icpr.errors import translate_error_code
from acme2certifier.cahandlers.ms_icpr.rpc import get_dce_rpc
from acme2certifier.cahandlers.ms_icpr.target import Target

NAME = "req"
MSRPC_UUID_ICPR = uuidtup_to_bin(("91ae6020-9e3c-11cf-8d7c-00aa00c091be", "0.0"))


def csr_pem_to_der(csr: str) -> bytes:
    """convert pem to der"""
    csr = x509.load_pem_x509_csr(csr)
    return csr.public_bytes(Encoding.DER)


def der_to_pem(certificate: bytes) -> bytes:
    """convert der to pem"""
    cert = x509.load_der_x509_certificate(certificate)
    return cert.public_bytes(Encoding.PEM)


def ca_chain_pem_from_cms(
    cms_der: bytes, leaf_der: Optional[bytes] = None
) -> Optional[bytes]:
    """Extract CA certificates from a CMS/PKCS#7 blob as concatenated PEM.

    MS-ICPR CertServerRequest returns the issued leaf + chain in pctbCert
    (mapped to MS-WCCE pctbCertChain). The leaf is stripped when leaf_der is
    provided so the result can be appended to the issued certificate.
    """
    if not cms_der:
        return None

    try:
        certificates = load_der_pkcs7_certificates(cms_der)
    except Exception as err:
        logging.warning("Failed to parse CMS certificate chain from pctbCert: %s", err)
        return None

    pem_parts = []
    for certificate in certificates:
        cert_der = certificate.public_bytes(Encoding.DER)
        if leaf_der is not None and cert_der == leaf_der:
            continue
        pem_parts.append(certificate.public_bytes(Encoding.PEM))

    if not pem_parts:
        return None
    return b"".join(pem_parts)


class DCERPCSessionError(rpcrt.DCERPCException):
    """error class"""

    def __init__(self, error_string=None, error_code=None, packet=None):
        rpcrt.DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self) -> str:
        self.error_code &= 0xFFFFFFFF
        error_msg = translate_error_code(self.error_code)
        return "RequestSessionError: %s" % error_msg


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/d6bee093-d862-4122-8f2b-7b49102097dc
class CERTTRANSBLOB(NDRSTRUCT):
    """certtransblob"""

    structure = (
        ("cb", ULONG),
        ("pb", PBYTE),
    )


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/0c6f150e-3ead-4006-b37f-ebbf9e2cf2e7
class CertServerRequest(NDRCALL):
    """certserver request"""

    opnum = 0
    structure = (
        ("dwFlags", DWORD),
        ("pwszAuthority", LPWSTR),
        ("pdwRequestId", DWORD),
        ("pctbAttribs", CERTTRANSBLOB),
        ("pctbRequest", CERTTRANSBLOB),
    )


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/0c6f150e-3ead-4006-b37f-ebbf9e2cf2e7
class CertServerRequestResponse(NDRCALL):
    """certserverresponse"""

    structure = (
        ("pdwRequestId", DWORD),
        ("pdwDisposition", ULONG),
        ("pctbCert", CERTTRANSBLOB),
        ("pctbEncodedCert", CERTTRANSBLOB),
        ("pctbDispositionMessage", CERTTRANSBLOB),
    )


def _certtransblob(data: bytes) -> CERTTRANSBLOB:
    """Wrap raw bytes in a CERTTRANSBLOB."""
    blob = CERTTRANSBLOB()
    blob["cb"] = len(data)
    blob["pb"] = data
    return blob


def _blob_bytes(blob: Any) -> bytes:
    """Join NDR CERTTRANSBLOB payload bytes."""
    return b"".join(blob["pb"])


def _decode_disposition_message(raw: bytes) -> Optional[str]:
    """Decode a UTF-16LE disposition message, if present."""
    if not raw:
        return None
    try:
        return raw.decode("utf-16le").strip()
    except Exception:
        return None


def _extract_issued_certificate(
    response: Any,
) -> Tuple[Optional[bytes], Optional[bytes]]:
    """Parse issued leaf PEM and optional CA chain from an enrollment response."""
    cert_der = _blob_bytes(response["pctbEncodedCert"])
    if not cert_der:
        logging.error("Certificate request was issued but no certificate was returned")
        return None, None

    cert_pem = der_to_pem(cert_der)
    cms_der = _blob_bytes(response["pctbCert"])
    if not cms_der:
        logging.debug("Enrollment response did not include pctbCert chain data")
        return cert_pem, None

    certificate_chain = ca_chain_pem_from_cms(cms_der, cert_der)
    if certificate_chain:
        logging.info("Extracted CA certificate chain from enrollment response")
    else:
        logging.warning(
            "Enrollment response contained pctbCert but no CA "
            "certificates could be extracted"
        )
    return cert_pem, certificate_chain


def _dce_request(dce: Any, rpc_request: CertServerRequest) -> Any:
    """Submit a CertServerRequest and return the untyped Impacket response."""
    return dce.request(rpc_request)


def _log_enrollment_error(error_code: int, disposition_message: Optional[str]) -> None:
    """Log a non-issued, non-pending enrollment disposition."""
    error_msg = translate_error_code(error_code)
    if "unknown error code" in error_msg:
        logging.error(
            "Got unknown error while trying to request certificate: (%s): %s"
            % (error_msg, disposition_message)
        )
        return
    logging.error("Got error while trying to request certificate: %s" % error_msg)


class Request:
    """request"""

    # pylint: disable=c0103
    def __init__(
        self,
        target: Target = None,
        ca: str = None,
        template: str = None,
        alt: str = None,
        debug=False,
        do_kerberos=False,
        **kwargs,
    ):
        self.target = target
        self.ca = ca
        self.template = template
        self.alt_name = alt
        self.request_id = 0
        self.verbose = debug
        self.kwargs = kwargs
        self.do_kerberos = do_kerberos
        self.dce = get_dce_rpc(
            MSRPC_UUID_ICPR,
            r"\pipe\cert",
            self.target,
            timeout=self.target.timeout,
            verbose=self.verbose,
            do_kerberos=self.do_kerberos,
        )

    def __enter__(self) -> "Request":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.close()
        return False

    def close(self) -> None:
        """Disconnect DCE/RPC session if connected."""
        if self.dce is None:
            return
        try:
            self.dce.disconnect()
        except Exception as err:
            logging.warning("Failed to disconnect DCE/RPC session: %s", err)
        finally:
            self.dce = None

    def _request_attributes(self) -> bytes:
        """Build UTF-16LE request attributes for CertServerRequest."""
        attributes = ["CertificateTemplate:%s" % self.template]
        if self.alt_name is not None:
            attributes.append("SAN:upn=%s" % self.alt_name)
        return checkNullString("\n".join(attributes)).encode("utf-16le")

    def _build_cert_request(self, csr_der: bytes) -> CertServerRequest:
        """Assemble an MS-ICPR CertServerRequest."""
        request = CertServerRequest()
        request["dwFlags"] = 0
        request["pwszAuthority"] = checkNullString(self.ca)
        request["pdwRequestId"] = self.request_id
        request["pctbAttribs"] = _certtransblob(self._request_attributes())
        request["pctbRequest"] = _certtransblob(csr_der)
        return request

    def get_cert(self, csr: bytes) -> Dict[str, Any]:
        """submit certificate request and return structured response"""
        if self.dce is None:
            raise ConnectionError("DCE/RPC connection to CA server is not available")

        request = self._build_cert_request(csr_pem_to_der(csr))
        logging.info("Requesting certificate")
        response: Any = _dce_request(self.dce, request)

        error_code = response["pdwDisposition"]
        request_id = response["pdwRequestId"]
        disposition_message = _decode_disposition_message(
            _blob_bytes(response["pctbDispositionMessage"])
        )
        cert_pem = None
        certificate_chain = None

        if error_code == 3:
            logging.info("Successfully requested certificate")
            cert_pem, certificate_chain = _extract_issued_certificate(response)
        elif error_code == 5:
            logging.warning("Certificate request is pending approval")
        else:
            _log_enrollment_error(error_code, disposition_message)

        logging.info("Request ID is %d" % request_id)
        return {
            "request_id": request_id,
            "disposition": error_code,
            "disposition_message": disposition_message,
            "certificate": cert_pem,
            "certificate_chain": certificate_chain,
        }
