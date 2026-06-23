"""request.py"""

# pylint: disable=C0209, C0415, E0401, R0913, W1201
import logging
from typing import Any, Dict, Optional

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from impacket.dcerpc.v5 import rpcrt
from impacket.dcerpc.v5.dtypes import DWORD, LPWSTR, PBYTE, ULONG
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.nrpc import checkNullString
from impacket.uuid import uuidtup_to_bin

from examples.ca_handler.ms_wcce.errors import translate_error_code
from examples.ca_handler.ms_wcce.rpc import get_dce_rpc
from examples.ca_handler.ms_wcce.target import Target

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

    def get_cert(self, csr: bytes) -> Dict[str, Any]:
        """submit certificate request and return structured response"""
        csr = csr_pem_to_der(csr)

        attributes = ["CertificateTemplate:%s" % self.template]

        if self.alt_name is not None:
            attributes.append("SAN:upn=%s" % self.alt_name)

        attributes = checkNullString("\n".join(attributes)).encode("utf-16le")
        pctb_attribs = CERTTRANSBLOB()
        pctb_attribs["cb"] = len(attributes)
        pctb_attribs["pb"] = attributes

        pctb_request = CERTTRANSBLOB()
        pctb_request["cb"] = len(csr)
        pctb_request["pb"] = csr

        request = CertServerRequest()
        request["dwFlags"] = 0
        request["pwszAuthority"] = checkNullString(self.ca)
        request["pdwRequestId"] = self.request_id
        request["pctbAttribs"] = pctb_attribs
        request["pctbRequest"] = pctb_request

        logging.info("Requesting certificate")

        response = self.dce.request(request)

        error_code = response["pdwDisposition"]
        request_id = response["pdwRequestId"]
        disposition_message_raw = b"".join(response["pctbDispositionMessage"]["pb"])
        disposition_message: Optional[str] = None

        if disposition_message_raw:
            try:
                disposition_message = disposition_message_raw.decode("utf-16le").strip()
            except Exception:
                disposition_message = None

        cert_pem = None

        if error_code == 3:
            logging.info("Successfully requested certificate")
            cert_der = b"".join(response["pctbEncodedCert"]["pb"])
            if cert_der:
                cert_pem = der_to_pem(cert_der)
            else:
                logging.error(
                    "Certificate request was issued but no certificate was returned"
                )
        elif error_code == 5:
            logging.warning("Certificate request is pending approval")
        else:
            error_msg = translate_error_code(error_code)
            if "unknown error code" in error_msg:
                logging.error(
                    "Got unknown error while trying to request certificate: (%s): %s"
                    % (
                        error_msg,
                        disposition_message,
                    )
                )
            else:
                logging.error(
                    "Got error while trying to request certificate: %s" % error_msg
                )

        logging.info("Request ID is %d" % request_id)
        return {
            "request_id": request_id,
            "disposition": error_code,
            "disposition_message": disposition_message,
            "certificate": cert_pem,
        }
