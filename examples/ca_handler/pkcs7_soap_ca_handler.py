# -*- coding: utf-8 -*-
""" propritary soap_ca_handler """
from __future__ import print_function
# pylint: disable=C0209, E0401
import os
import binascii
import requests
import xmltodict
from pyasn1_modules import rfc2314, rfc2315
from pyasn1.codec.der import encoder, decoder
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from requests.structures import CaseInsensitiveDict
from acme_srv.helper import load_config, b64_url_recode, b64_decode, b64_encode, convert_byte_to_string, convert_string_to_byte


class CAhandler(object):
    """ EST CA  handler """

    def __init__(self, _debug=None, logger=None):
        self.logger = logger
        self.soap_srv = None
        self.profilename = None
        self.password = None
        self.signing_cert = None
        self.signing_key = None
        self.ca_bundle = False
        self.email = None

    def __enter__(self):
        """ Makes CAhandler a Context Manager """
        if not self.soap_srv:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _config_load(self):
        """" load config from file """
        self.logger.debug('CAhandler._config_load()')

        config_dic = load_config(self.logger, 'CAhandler')

        if 'soap_srv' in config_dic['CAhandler']:
            self.soap_srv = config_dic['CAhandler']['soap_srv']
        else:
            self.logger.error('CAhandler._config_load(): soap_srv option is missing on config file')

        if 'signing_cert' in config_dic['CAhandler']:
            if os.path.exists(config_dic['CAhandler']['signing_cert']):
                with open(config_dic['CAhandler']['signing_cert'], 'rb') as open_file:
                    self.signing_cert = x509.load_pem_x509_certificate(open_file.read(), default_backend())
            else:
                self.logger.error('CAhandler._config_load(): signing_cert {0} not found.'.format(config_dic['CAhandler']['signing_cert']))
        else:
            self.logger.error('CAhandler._config_load(): signing_cert option is missing on config file')

        if 'signing_key' in config_dic['CAhandler']:
            if os.path.exists(config_dic['CAhandler']['signing_key']):
                with open(config_dic['CAhandler']['signing_key'], 'rb') as open_file:
                    self.signing_key = serialization.load_pem_private_key(
                        open_file.read(), password=self.password, backend=default_backend())
            else:
                self.logger.error('CAhandler._config_load(): signing_key {0} not found.'.format(config_dic['CAhandler']['signing_key']))
        else:
            self.logger.error('CAhandler._config_load(): signing_key option is missing on config file')

        if 'profilename' in config_dic['CAhandler']:
            self.profilename = config_dic['CAhandler']['profilename']
        else:
            self.logger.error('CAhandler._config_load(): profilename option is missing on config file')

        if 'email' in config_dic['CAhandler']:
            self.email = config_dic['CAhandler']['email']
        else:
            self.logger.error('CAhandler._config_load(): email option is missing on config file')

        self.logger.debug('CAhandler._config_load() ended')

    def _stub_func(self, parameter):
        """" load config from file """
        self.logger.debug('CAhandler._stub_func({0})'.format(parameter))

        self.logger.debug('CAhandler._stub_func() ended')

    def _cert_decode(self, cert):
        self.logger.debug('CAhandler._cert_decode()')
        return decoder.decode(cert.public_bytes(serialization.Encoding.DER), asn1Spec=rfc2315.Certificate())

    def _sign(self, key, payload):
        """Signs the payload with the specified key"""

        signature_algorithm = rfc2314.AlgorithmIdentifier()

        if isinstance(key, rsa.RSAPrivateKey):
            # sha256WithRSAEncryption. MUST have ASN.1 NULL in the parameters field
            signature_algorithm.setComponentByName('algorithm', (1, 2, 840, 113549, 1, 1, 11))
            signature_algorithm.setComponentByName('parameters', '\x05\x00')
            signature = key.sign(
                payload,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            # ecdsaWithSHA256. MUST omit the parameters field
            signature_algorithm.setComponentByName('algorithm', (1, 2, 840, 10045, 4, 3, 2))
            signature = key.sign(
                payload,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            # raise UnsupportedKeyTypeError
            pass

        return signature, signature_algorithm

    def _create_pkcs7(self, cert, csr, private_key):
        """Creates the PKCS7 structure and signs it"""
        self.logger.debug('CAhandler._create_pkcs7()')
        content_info = rfc2315.ContentInfo()
        content_info.setComponentByName('contentType', rfc2315.data)
        content_info.setComponentByName('content', encoder.encode(rfc2315.Data(csr)))

        issuer_and_serial = rfc2315.IssuerAndSerialNumber()
        issuer_and_serial.setComponentByName('issuer', cert[0]['tbsCertificate']['issuer'])
        issuer_and_serial.setComponentByName('serialNumber', cert[0]['tbsCertificate']['serialNumber'])

        raw_signature, _ = self._sign(private_key, csr)
        signature = rfc2314.univ.OctetString(hexValue=binascii.hexlify(raw_signature).decode('ascii'))

        # Microsoft adds parameters with ASN.1 NULL encoding here,
        # but according to rfc5754 they should be absent:
        # "Implementations MUST generate SHA2 AlgorithmIdentifiers with absent parameters."
        sha2 = rfc2315.AlgorithmIdentifier()
        sha2.setComponentByName('algorithm', (2, 16, 840, 1, 101, 3, 4, 2, 1))

        alg_from_cert = cert[0]['tbsCertificate']['subjectPublicKeyInfo']['algorithm']['algorithm']
        digest_encryption_algorithm = rfc2315.AlgorithmIdentifier()
        digest_encryption_algorithm.setComponentByName('algorithm', alg_from_cert)
        digest_encryption_algorithm.setComponentByName('parameters', '\x05\x00')

        signer_info = rfc2315.SignerInfo()
        signer_info.setComponentByName('version', 1)
        signer_info.setComponentByName('issuerAndSerialNumber', issuer_and_serial)
        signer_info.setComponentByName('digestAlgorithm', sha2)
        signer_info.setComponentByName('digestEncryptionAlgorithm', digest_encryption_algorithm)
        signer_info.setComponentByName('encryptedDigest', signature)

        signer_infos = rfc2315.SignerInfos().setComponents(signer_info)

        digest_algorithms = rfc2315.DigestAlgorithmIdentifiers().setComponents(sha2)

        extended_cert_or_cert = rfc2315.ExtendedCertificateOrCertificate()
        extended_cert_or_cert.setComponentByName('certificate', cert[0])

        extended_certs_and_cert = rfc2315.ExtendedCertificatesAndCertificates().subtype(
            implicitTag=rfc2315.tag.Tag(rfc2315.tag.tagClassContext,
                                        rfc2315.tag.tagFormatConstructed, 0))
        extended_certs_and_cert.setComponents(extended_cert_or_cert)

        signed_data = rfc2315.SignedData()
        signed_data.setComponentByName('version', 1)
        signed_data.setComponentByName('digestAlgorithms', digest_algorithms)
        signed_data.setComponentByName('contentInfo', content_info)
        signed_data.setComponentByName('certificates', extended_certs_and_cert)
        signed_data.setComponentByName('signerInfos', signer_infos)

        outer_content_info = rfc2315.ContentInfo()
        outer_content_info.setComponentByName('contentType', rfc2315.signedData)
        outer_content_info.setComponentByName('content', encoder.encode(signed_data))

        return encoder.encode(outer_content_info)

    def _soaprequest_build(self, pkcs7):
        """ build soap request payload """
        self.logger.debug('CAhandler._soaprequest_build()')
        data = """
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:aur="http://monetplus.cz/services/kb/aurora">
        <soapenv:Header/>
        <soapenv:Body>
            <aur:RequestCertificate>
                <aur:request>
                    <aur:ProfileName>{0}</aur:ProfileName>
                    <aur:CertificateRequestRaw>{1}</aur:CertificateRequestRaw>
                    <aur:Email>requester{2}</aur:Email>
                    <aur:ReturnCertificateCaChain>true</aur:ReturnCertificateCaChain>
                </aur:request>
            </aur:RequestCertificate>
        </soapenv:Body>
        </soapenv:Envelope>
        """.format(self.profilename, pkcs7, self.email)  # pylint: disable=c0209

        return data

    def _soaprequest_send(self, payload):
        """ forward csr to ca server """
        self.logger.debug('CAhandler._soaprequest_send()')

        headers = CaseInsensitiveDict()
        headers["Content-Type"] = "application/soap+xml"

        b64_cert_bundle = None
        error = None

        try:
            resp = requests.post(self.soap_srv, headers=headers, verify=self.ca_bundle, data=payload, timeout=20)
            if resp.status_code == 200:
                soap_dic = xmltodict.parse(resp.text)
                try:
                    b64_cert_bundle = soap_dic['s:Envelope']['s:Body']['RequestCertificateResponse']['RequestCertificateResult']['IssuedCertificate']
                except Exception:
                    self.logger.error('CAhandler._soaprequest_send() - XML Parsing error')
                    self.logger.debug('CAhandler._soaprequest_send(): {0}'.format(resp.text))
            else:
                self.logger.error('CAhandler._soaprequest_send(): http status_code {0}'.format(resp.status_code))
                error: 'server error'
                try:
                    soap_dic = xmltodict.parse(resp.text)
                    self.logger.error('CAhandler._soaprequest_send() - faultcode: {0}'.format(soap_dic['s:Envelope']['s:Body']['s:Fault']['faultcode']))
                    self.logger.error('CAhandler._soaprequest_send() - faultstring: {0}'.format(soap_dic['s:Envelope']['s:Body']['s:Fault']['faultstring']))
                except Exception:
                    self.logger.error('CAhandler._soaprequest_send() - unkown error')
                    self.logger.debug('CAhandler._soaprequest_send(): {0}'.format(resp.text))

        except Exception as err:
            self.logger.error('CAhandler._soaprequest_send(): {0}'.format(err))
            error = 'Connection error'
            payload = None
            resp = None

        return (error, b64_cert_bundle)

    def _get_certificate(self, signature_block_file):
        """Extracts a DER certificate from JAR Signature's "Signature Block File".

        :param signature_block_file: file bytes (as string) representing the
        certificate, as read directly out of the APK/ZIP

        :return: A binary representation of the certificate's public key,
        or None in case of error

        """
        content = decoder.decode(signature_block_file, asn1Spec=rfc2315.ContentInfo())[0]
        if content.getComponentByName('contentType') != rfc2315.signedData:
            return None
        content = decoder.decode(content.getComponentByName('content'), asn1Spec=rfc2315.SignedData())[0]

        cert_list = []
        for cert in content.getComponentByName('certificates'):
            # cert_obj = x509.load_der_x509_certificate(cert, default_backend())
            # print(encoder.encode(cert))
            cert_obj = x509.load_der_x509_certificate(encoder.encode(cert), default_backend())
            cert_pem = cert_obj.public_bytes(serialization.Encoding.PEM)
            cert_list.append(convert_byte_to_string(cert_pem))

        return cert_list

    def _certraw_get(self, pem_data):
        """ get raw certificate as required by a2c """
        self.logger.debug('CAhandler._certraw_get()')

        cert = x509.load_pem_x509_certificate(convert_string_to_byte(pem_data), default_backend())
        # DER cert
        cert_val = cert.public_bytes(serialization.Encoding.DER)

        return b64_encode(self.logger, cert_val)

    def enroll(self, csr):
        """ enroll certificate  """
        self.logger.debug('CAhandler.enroll()')

        cert_bundle = None
        error = None
        cert_raw = None
        poll_indentifier = None

        # convert csr to DER format
        csr_der = b64_decode(self.logger, b64_url_recode(self.logger, csr))
        # create pkcs7 bundle
        decoded_cert = self._cert_decode(self.signing_cert)
        pkcs7_bundle = self._create_pkcs7(decoded_cert, csr_der, self.signing_key)

        # build and soap request to be send to ca server
        payload = self._soaprequest_build(b64_encode(self.logger, pkcs7_bundle))
        (error, b64_cert_bundle) = self._soaprequest_send(payload)

        if not error and b64_cert_bundle:
            # extract certificates from pkcs7 bundle we got as response
            certificate_list = self._get_certificate(b64_decode(self.logger, b64_cert_bundle))

            # create pem bundle and raw file
            cert_bundle = ''.join(certificate_list)
            cert_raw = self._certraw_get(certificate_list[0])

        self.logger.debug('Certificate.enroll() ended')

        return (error, cert_bundle, cert_raw, poll_indentifier)

    def poll(self, cert_name, poll_identifier, _csr):
        """ poll status of pending CSR and download certificates """
        self.logger.debug('CAhandler.poll()')

        error = None
        cert_bundle = None
        cert_raw = None
        rejected = False
        self._stub_func(cert_name)

        self.logger.debug('CAhandler.poll() ended')
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(self, _cert, _rev_reason, _rev_date):
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke()')

        code = 500
        message = 'urn:ietf:params:acme:error:serverInternal'
        detail = 'Revocation is not supported.'

        self.logger.debug('Certificate.revoke() ended')
        return (code, message, detail)

    def trigger(self, payload):
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')

        error = None
        cert_bundle = None
        cert_raw = None
        self._stub_func(payload)

        self.logger.debug('CAhandler.trigger() ended with error: {0}'.format(error))
        return (error, cert_bundle, cert_raw)
