"""
A Python client for the Microsoft AD Certificate Services web page.

https://github.com/magnuswatn/certsrv
"""
# pylint: disable=C0209, C0415, R1720, R1705
import os
import re
import base64
import logging
import warnings
import requests

__version__ = "2.1.1"

logger = logging.getLogger(__name__)

TIMEOUT = 30
UNKOWN_ERR_MSG = "An unknown error occured"
DEPRECATIONWARNING = "This function is deprecated. Use the method on the Certsrv class instead"


class RequestDeniedException(Exception):
    """Signifies that the request was denied by the ADCS server."""

    def __init__(self, message, response):
        Exception.__init__(self, message)
        self.response = response


class CouldNotRetrieveCertificateException(Exception):
    """Signifies that the certificate could not be retrieved."""

    def __init__(self, message, response):
        Exception.__init__(self, message)
        self.response = response


class CertificatePendingException(Exception):
    """Signifies that the request needs to be approved by a CA admin."""

    def __init__(self, req_id):
        Exception.__init__(
            self,
            "Your certificate request has been received. "
            "However, you must wait for an administrator to issue the "
            "certificate you requested. Your Request Id is {0}.".format(req_id),
        )
        self.req_id = req_id


class Certsrv(object):
    """
    Represents a Microsoft AD Certificate Services web server.

    Args:
        server: The FQDN to a server running the Certification Authority
            Web Enrollment role (must be listening on https).
        username: The username for authentication.
        password: The password for authentication.
        auth_method: The chosen authentication method. Either 'basic' (the default),
            'ntlm' or 'cert' (SSL client certificate).
        cafile: A PEM file containing the CA certificates that should be trusted.
        timeout: The timeout to use against the CA server, in seconds.
            The default is 30.

    Note:
        If you use a client certificate for authentication (auth_method=cert),
        the username parameter should be the path to a certificate, and
        the password parameter the path to a (unencrypted) private key.
    """
    # pylint: disable=r0913
    def __init__(self, server, username, password, auth_method="basic",
                 cafile=None, timeout=TIMEOUT, proxies=None):

        self.server = server
        self.timeout = timeout
        self.auth_method = auth_method
        self.session = requests.Session()
        self.proxies = proxies

        if cafile:
            self.session.verify = cafile
        else:
            # requests uses it's own CA bundle by default
            # but ADCS servers often have certificates
            # from private CAs that are locally trusted,
            # so we try to find, and use, the system bundle
            # instead. Fallback to requests own.
            self.session.verify = _get_ca_bundle()

        self._set_credentials(username, password)

        # We need certsrv to think we are a browser,
        # or otherwise the Content-Type of the retrieved
        # certificate will be wrong (for some reason).
        self.session.headers = {
            "User-agent": "Mozilla/5.0 certsrv (https://github.com/magnuswatn/certsrv)"
        }

    def _set_credentials(self, username, password):
        if self.auth_method == "ntlm":
            from requests_ntlm import HttpNtlmAuth

            self.session.auth = HttpNtlmAuth(username, password)
        elif self.auth_method == "cert":
            self.session.cert = (username, password)
        else:
            self.session.auth = (username, password)

    def _post(self, url, **kwargs):
        response = self.session.post(url, timeout=self.timeout, proxies=self.proxies, **kwargs)
        return self._handle_response(response)

    def _get(self, url, **kwargs):
        response = self.session.get(url, timeout=self.timeout, proxies=self.proxies, **kwargs)
        return self._handle_response(response)

    @staticmethod
    def _handle_response(response):

        logger.debug(
            "Sent %s request to %s, with headers:\n%s\n\nand body:\n%s",
            response.request.method,
            response.request.url,
            "\n".join(
                ["{0}: {1}".format(k, v) for k, v in response.request.headers.items()]
            ),
            response.request.body,
        )

        try:
            debug_content = response.content.decode()
        except UnicodeDecodeError:
            debug_content = base64.b64encode(response.content)

        logger.debug(
            "Recieved response:\nHTTP %s\n%s\n\n%s",
            response.status_code,
            "\n".join(["{0}: {1}".format(k, v) for k, v in response.headers.items()]),
            debug_content,
        )

        response.raise_for_status()

        return response

    def get_cert(self, csr, template, encoding="b64", attributes=None):
        """
        Gets a certificate from the ADCS server.

        Args:
            csr: The certificate request to submit.
            template: The certificate template the cert should be issued from.
            encoding: The desired encoding for the returned certificate.
                Possible values are 'bin' for binary and 'b64' for Base64 (PEM).
            attributes: Additional Attributes (request attibutes) to be sent along with
                the request.

        Returns:
            The issued certificate.

        Raises:
            RequestDeniedException: If the request was denied by the ADCS server.
            CertificatePendingException: If the request needs to be approved
                by a CA admin.
            CouldNotRetrieveCertificateException: If something went wrong while
                fetching the cert.
        """
        cert_attrib = "CertificateTemplate:{0}\r\n".format(template)
        if attributes:
            cert_attrib += attributes

        data = {
            "Mode": "newreq",
            "CertRequest": csr,
            "CertAttrib": cert_attrib,
            "FriendlyType": "Saved-Request Certificate",
            "TargetStoreFlags": "0",
            "SaveCert": "yes",
        }

        url = "https://{0}/certsrv/certfnsh.asp".format(self.server)

        response = self._post(url, data=data)

        # We need to parse the Request ID from the returning HTML page
        try:
            req_id = re.search(r"certnew.cer\?ReqID=(\d+)&", response.text).group(1)
        except AttributeError:
            # We didn't find any request ID in the response. It may need approval.
            if re.search(r"Certificate Pending", response.text):
                req_id = re.search(r"Your Request Id is (\d+).", response.text).group(1)
                # pylint: disable=w0707
                raise CertificatePendingException(req_id)
            else:
                # Must have failed. Lets find the error message
                # and raise a RequestDeniedException.
                try:
                    error = re.search(
                        r'The disposition message is "([^"]+)', response.text
                    ).group(1)
                except AttributeError:
                    error = UNKOWN_ERR_MSG
                # pylint: disable=w0707
                raise RequestDeniedException(error, response.text)

        return self.get_existing_cert(req_id, encoding)

    def get_existing_cert(self, req_id, encoding="b64"):
        """
        Gets a certificate that has already been created from the ADCS server.

        Args:
            req_id: The request ID to retrieve.
            encoding: The desired encoding for the returned certificate.
                Possible values are 'bin' for binary and 'b64' for Base64 (PEM).

        Returns:
            The issued certificate.

        Raises:
            CouldNotRetrieveCertificateException: If something went wrong
                while fetching the cert.
        """

        cert_url = "https://{0}/certsrv/certnew.cer".format(self.server)
        params = {"ReqID": req_id, "Enc": encoding}

        response = self._get(cert_url, params=params)

        if response.headers["Content-Type"] != "application/pkix-cert":
            # The response was not a cert. Something must have gone wrong
            try:
                error = re.search(
                    "Disposition message:[^\t]+\t\t([^\r\n]+)", response.text
                ).group(1)

            except AttributeError:
                error = UNKOWN_ERR_MSG
            raise CouldNotRetrieveCertificateException(error, response.text)
        else:
            return response.content

    def get_ca_cert(self, encoding="b64"):
        """
        Gets the (newest) CA certificate from the ADCS server.

        Args:
            encoding: The desired encoding for the returned certificate.
                Possible values are 'bin' for binary and 'b64' for Base64 (PEM).

        Returns:
            The newest CA certificate from the server.
        """
        url = "https://{0}/certsrv/certcarc.asp".format(self.server)

        response = self._get(url)

        # We have to check how many renewals this server has had,
        # so that we get the newest CA cert.
        renewals = re.search(r"var nRenewals=(\d+);", response.text).group(1)

        cert_url = "https://{0}/certsrv/certnew.cer".format(self.server)
        params = {"ReqID": "CACert", "Enc": encoding, "Renewal": renewals}

        response = self._get(cert_url, params=params)

        if response.headers["Content-Type"] != "application/pkix-cert":
            raise CouldNotRetrieveCertificateException(
                UNKOWN_ERR_MSG, response.content
            )

        return response.content

    def get_chain(self, encoding="bin"):
        """
        Gets the CA chain from the ADCS server.

        Args:
            encoding: The desired encoding for the returned certificates.
                Possible values are 'bin' for binary and 'b64' for Base64 (PEM).

        Returns:
            The CA chain from the server, in PKCS#7 format.
        """
        url = "https://{0}/certsrv/certcarc.asp".format(self.server)

        response = self._get(url)

        # We have to check how many renewals this server has had, so that we get the newest chain
        renewals = re.search(r"var nRenewals=(\d+);", response.text).group(1)

        chain_url = "https://{0}/certsrv/certnew.p7b".format(self.server)
        params = {"ReqID": "CACert", "Renewal": renewals, "Enc": encoding}

        chain_response = self._get(chain_url, params=params)

        if chain_response.headers["Content-Type"] != "application/x-pkcs7-certificates":
            raise CouldNotRetrieveCertificateException(
                UNKOWN_ERR_MSG, chain_response.content
            )

        return chain_response.content

    def check_credentials(self):
        """
        Checks the specified credentials against the ADCS server.

        Returns:
            True if authentication succeeded, False if it failed.
        """
        url = "https://{0}/certsrv/".format(self.server)

        try:
            self._get(url)
        except requests.exceptions.HTTPError as error:
            if error.response.status_code == 401:
                return False
            else:
                raise
        return True

    def update_credentials(self, username, password):
        """
        Updates the credentials used against the ADCS server.

        Args:
            username: The username for authentication.
            password: The password for authentication.
        """
        if self.auth_method in ("ntlm", "cert"):
            # NTLM and SSL is connection based,
            # so we need to close the connection
            # to be able to re-authenticate
            self.session.close()
        self._set_credentials(username, password)


def _get_ca_bundle():
    """Tries to find the platform ca bundle for the system (on linux systems)"""
    ca_bundles = [
        # list taken from https://golang.org/src/crypto/x509/root_linux.go
        "/etc/ssl/certs/ca-certificates.crt",                 # Debian/Ubuntu/Gentoo etc.
        "/etc/pki/tls/certs/ca-bundle.crt",                   # Fedora/RHEL 6
        "/etc/ssl/ca-bundle.pem",                             # OpenSUSE
        "/etc/pki/tls/cacert.pem",                            # OpenELEC
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  # CentOS/RHEL 7
    ]
    for ca_bundle in ca_bundles:
        if os.path.isfile(ca_bundle):
            return ca_bundle
    # if the bundle was not found, we revert back to requests own
    return True


# pylint: disable=r0913
def get_cert(server, csr, template, username, password, encoding="b64", **kwargs):
    """
    Gets a certificate from a Microsoft AD Certificate Services web page.

    Args:
        server: The FQDN to a server running the Certification Authority
            Web Enrollment role (must be listening on https).
        csr: The certificate request to submit.
        template: The certificate template the cert should be issued from.
        username: The username for authentication.
        pasword: The password for authentication.
        encoding: The desired encoding for the returned certificate.
            Possible values are 'bin' for binary and 'b64' for Base64 (PEM).
        auth_method: The chosen authentication method. Either 'basic' (the default),
            'ntlm' or 'cert' (ssl client certificate).
        cafile: A PEM file containing the CA certificates that should be trusted.

    Returns:
        The issued certificate.

    Raises:
        RequestDeniedException: If the request was denied by the ADCS server.
        CertificatePendingException: If the request needs to be approved by a CA admin.
        CouldNotRetrieveCertificateException: If something went wrong while
            fetching the cert.

    Note:
        This method is deprecated.

    """
    warnings.warn(
        DEPRECATIONWARNING,
        DeprecationWarning,
    )
    certsrv = Certsrv(server, username, password, **kwargs)
    return certsrv.get_cert(csr, template, encoding)


def get_existing_cert(server, req_id, username, password, encoding="b64", **kwargs):
    """
    Gets a certificate that has already been created from a
    Microsoft AD Certificate Services web page.

    Args:
        server: The FQDN to a server running the Certification Authority
            Web Enrollment role (must be listening on https).
        req_id: The request ID to retrieve.
        username: The username for authentication.
        pasword: The password for authentication.
        encoding: The desired encoding for the returned certificate.
            Possible values are 'bin' for binary and 'b64' for Base64 (PEM).
        auth_method: The chosen authentication method. Either 'basic' (the default),
            'ntlm' or 'cert' (ssl client certificate).
        cafile: A PEM file containing the CA certificates that should be trusted.

    Returns:
        The issued certificate.

    Raises:
        CouldNotRetrieveCertificateException: If something went wrong while
            fetching the cert.

    Note:
        This method is deprecated.
    """
    warnings.warn(
        DEPRECATIONWARNING,
        DeprecationWarning,
    )
    certsrv = Certsrv(server, username, password, **kwargs)
    return certsrv.get_existing_cert(req_id, encoding)


def get_ca_cert(server, username, password, encoding="b64", **kwargs):
    """
    Gets the (newest) CA certificate from a Microsoft AD Certificate Services web page.

    Args:
        server: The FQDN to a server running the Certification Authority
            Web Enrollment role (must be listening on https).
        username: The username for authentication.
        pasword: The password for authentication.
        encoding: The desired encoding for the returned certificate.
            Possible values are 'bin' for binary and 'b64' for Base64 (PEM).
        auth_method: The chosen authentication method. Either 'basic' (the default),
            'ntlm' or 'cert' (ssl client certificate).
        cafile: A PEM file containing the CA certificates that should be trusted.

    Returns:
        The newest CA certificate from the server.

    Note:
        This method is deprecated.
    """
    warnings.warn(
        DEPRECATIONWARNING,
        DeprecationWarning,
    )
    certsrv = Certsrv(server, username, password, **kwargs)
    return certsrv.get_ca_cert(encoding)


def get_chain(server, username, password, encoding="bin", **kwargs):
    """
    Gets the chain from a Microsoft AD Certificate Services web page.

    Args:
        server: The FQDN to a server running the Certification Authority
            Web Enrollment role (must be listening on https).
        username: The username for authentication.
        pasword: The password for authentication.
        encoding: The desired encoding for the returned certificates.
            Possible values are 'bin' for binary and 'b64' for Base64 (PEM).
        auth_method: The chosen authentication method. Either 'basic' (the default),
            'ntlm' or 'cert' (ssl client certificate).
        cafile: A PEM file containing the CA certificates that should be trusted.

    Returns:
        The CA chain from the server, in PKCS#7 format.

    Note:
        This method is deprecated.
    """
    warnings.warn(
        DEPRECATIONWARNING,
        DeprecationWarning,
    )
    certsrv = Certsrv(server, username, password, **kwargs)
    return certsrv.get_chain(encoding)


def check_credentials(server, username, password, **kwargs):
    """
    Checks the specified credentials against the specified ADCS server.

    Args:
        ca: The FQDN to a server running the Certification Authority
            Web Enrollment role (must be listening on https).
        username: The username for authentication.
        pasword: The password for authentication.
        auth_method: The chosen authentication method. Either 'basic' (the default),
            'ntlm' or 'cert' (ssl client certificate).
        cafile: A PEM file containing the CA certificates that should be trusted.

    Returns:
        True if authentication succeeded, False if it failed.

    Note:
        This method is deprecated.
    """
    warnings.warn(
        DEPRECATIONWARNING,
        DeprecationWarning,
    )
    certsrv = Certsrv(server, username, password, **kwargs)
    return certsrv.check_credentials()
