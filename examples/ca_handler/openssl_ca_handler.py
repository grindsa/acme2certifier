#!/usr/bin/python
# -*- coding: utf-8 -*-
""" ca hanlder for Insta Certifier via REST-API class """
from __future__ import print_function
import os
import json
import base64
import uuid
from OpenSSL import crypto
from acme.helper import load_config, build_pem_file, uts_now, uts_to_date_utc, b64_url_recode, cert_serial_get, convert_string_to_byte, convert_byte_to_string

class CAhandler(object):
    """ CA  handler """

    def __init__(self, debug=None, logger=None):
        self.debug = debug
        self.logger = logger
        self.issuer_dict = {
            'issuing_ca_key' : None,
            'issuing_ca_cert' : None,
            'issuing_ca_crl'  : None,
        }
        self.ca_cert_chain_list = []
        self.cert_validity_days = 365
        self.openssl_conf = None
        self.cert_save_path = None

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        if not self.issuer_dict['issuing_ca_key']:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _ca_load(self):
        """ load ca key and cert """
        self.logger.debug('CAhandler._ca_load()')
        ca_key = None
        ca_cert = None
        # open key and cert
        if 'issuing_ca_key' in self.issuer_dict:
            if os.path.exists(self.issuer_dict['issuing_ca_key']):
                if 'passphrase' in self.issuer_dict:
                    with open(self.issuer_dict['issuing_ca_key'], 'r') as fso:
                        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, fso.read(), convert_string_to_byte(self.issuer_dict['passphrase']))
                else:
                    with open(self.issuer_dict['issuing_ca_key'], 'r') as fso:
                        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, fso.read())
        if 'issuing_ca_cert' in self.issuer_dict:
            if os.path.exists(self.issuer_dict['issuing_ca_cert']):
                with open(self.issuer_dict['issuing_ca_cert'], 'r') as fso:
                    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, fso.read())
        self.logger.debug('CAhandler._ca_load() endet')
        return(ca_key, ca_cert)

    def _certificate_chain_verify(self, cert, ca_cert):
        """ verify certificate chain """
        self.logger.debug('CAhandler._certificate_chain_verify()')

        pem_file = build_pem_file(self.logger, None, b64_url_recode(self.logger, cert), True)
        try:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_file)
        except BaseException:
            cert = None

        if cert:
            error = None
            #Create a certificate store and add ca cert(s)
            try:
                store = crypto.X509Store()
                store.add_cert(ca_cert)
            except BaseException:
                error = 'issuing certificate could not be added to trust-store'

            if not error:
                # add ca chain to truststore
                for cert_name in self.ca_cert_chain_list:
                    try:
                        with open(cert_name, 'r') as fso:
                            cain_cert = crypto.load_certificate(crypto.FILETYPE_PEM, fso.read())
                        store.add_cert(cain_cert)
                    except BaseException:
                        error = 'certificate {0} could not be added to trust store'.format(cert_name)

            if not error:
                # Create a certificate context using the store and the downloaded certificate
                store_ctx = crypto.X509StoreContext(store, cert)
                # Verify the certificate, returns None if it can validate the certificate
                try:
                    result = store_ctx.verify_certificate()
                except BaseException as err:
                    result = str(err)
            else:
                result = error
        else:
            result = 'certificate could not get parsed'

        self.logger.debug('CAhandler._certificate_chain_verify() ended with {0}'.format(result))
        return result

    def _config_check(self):
        """ check config for consitency """
        self.logger.debug('CAhandler._config_check()')
        error = None
        if 'issuing_ca_key' in self.issuer_dict and self.issuer_dict['issuing_ca_key']:
            if not os.path.exists(self.issuer_dict['issuing_ca_key']):
                error = 'issuing_ca_key {0} does not exist'.format(self.issuer_dict['issuing_ca_key'])
        else:
            error = 'issuing_ca_key not specfied in config_file'

        if not error:
            if 'issuing_ca_cert' in self.issuer_dict and self.issuer_dict['issuing_ca_cert']:
                if not os.path.exists(self.issuer_dict['issuing_ca_cert']):
                    error = 'issuing_ca_cert {0} does not exist'.format(self.issuer_dict['issuing_ca_cert'])
            else:
                error = 'issuing_ca_cert must be specified in config file'

        if not error:
            if 'issuing_ca_crl' in self.issuer_dict and self.issuer_dict['issuing_ca_crl']:
                if not os.path.exists(self.issuer_dict['issuing_ca_crl']):
                    error = 'issuing_ca_crl {0} does not exist'.format(self.issuer_dict['issuing_ca_crl'])
            else:
                error = 'issuing_ca_crl must be specified in config file'

        if not error:
            if self.cert_save_path:
                if not os.path.exists(self.cert_save_path):
                    error = 'cert_save_path {0} does not exist'.format(self.cert_save_path)
            else:
                error = 'cert_save_path must be specified in config file'

        if not error:
            if self.openssl_conf:
                if not os.path.exists(self.openssl_conf):
                    error = 'openssl_conf {0} does not exist'.format(self.openssl_conf)

        if not error and not self.ca_cert_chain_list:
            error = 'ca_cert_chain_list must be specified in config file'

        if error:
            self.logger.debug('CAhandler config error: {0}'.format(error))

        self.logger.debug('CAhandler._config_check() ended'.format())
        return error

    def _config_load(self):
        """" load config from file """
        self.logger.debug('CAhandler._config_load()')
        config_dic = load_config(self.logger, 'CAhandler')

        if 'issuing_ca_key' in config_dic['CAhandler']:
            self.issuer_dict['issuing_ca_key'] = config_dic['CAhandler']['issuing_ca_key']
        if 'issuing_ca_cert' in config_dic['CAhandler']:
            self.issuer_dict['issuing_ca_cert'] = config_dic['CAhandler']['issuing_ca_cert']
        if 'issuing_ca_key_passphrase' in config_dic['CAhandler']:
            self.issuer_dict['passphrase'] = config_dic['CAhandler']['issuing_ca_key_passphrase']
        if 'ca_cert_chain_list' in config_dic['CAhandler']:
            self.ca_cert_chain_list = json.loads(config_dic['CAhandler']['ca_cert_chain_list'])
        if 'cert_validity_days' in config_dic['CAhandler']:
            self.cert_validity_days = int(config_dic['CAhandler']['cert_validity_days'])
        if 'cert_save_path' in config_dic['CAhandler']:
            self.cert_save_path = config_dic['CAhandler']['cert_save_path']
        if 'issuing_ca_crl' in config_dic['CAhandler']:
            self.issuer_dict['issuing_ca_crl'] = config_dic['CAhandler']['issuing_ca_crl']
        # convert passphrase
        if 'passphrase' in self.issuer_dict:
            self.issuer_dict['passphrase'] = self.issuer_dict['passphrase'].encode('ascii')
        if 'openssl_conf' in config_dic['CAhandler']:
            self.openssl_conf = config_dic['CAhandler']['openssl_conf']

        self.logger.debug('CAhandler._config_load() ended')

    def _crl_check(self, crl, serial):
        """ check if CRL already contains serial """
        self.logger.debug('CAhandler._crl_check()')
        sn_match = False
        serial = convert_string_to_byte(serial)
        if crl and serial:
            for rev in crl.get_revoked():
                if serial == rev.get_serial().lower():
                    sn_match = True
                    break
        self.logger.debug('CAhandler._crl_check() with:{0}'.format(sn_match))
        return sn_match

    def _pemcertchain_generate(self, ee_cert, issuer_cert):
        """ build pem chain """
        self.logger.debug('CAhandler._pemcertchain_generate()')

        if issuer_cert:
            pem_chain = '{0}{1}'.format(ee_cert, issuer_cert)
        else:
            pem_chain = ee_cert
        for cert in self.ca_cert_chain_list:
            if os.path.exists(cert):
                with open(cert, 'r') as fso:
                    cert_pem = fso.read()
                pem_chain = '{0}{1}'.format(pem_chain, cert_pem)

        self.logger.debug('CAhandler._pemcertchain_generate() ended')
        return pem_chain

    def enroll(self, csr):
        """ enroll certificate """
        self.logger.debug('CAhandler.enroll()')

        cert_bundle = None
        cert_raw = None

        error = self._config_check()

        if not error:
            try:
                # prepare the CSR
                csr = build_pem_file(self.logger, None, b64_url_recode(self.logger, csr), None, True)

                # load ca cert and key
                (ca_key, ca_cert) = self._ca_load()

                # creating a rest form CSR
                req = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)
                # sign csr
                cert = crypto.X509()
                cert.gmtime_adj_notBefore(0)
                cert.gmtime_adj_notAfter(self.cert_validity_days * 86400)
                cert.set_issuer(ca_cert.get_subject())
                cert.set_subject(req.get_subject())
                cert.set_pubkey(req.get_pubkey())
                cert.set_serial_number(uuid.uuid4().int)
                cert.set_version(2)
                # cert.set_serial_number(uts_now())
                cert.add_extensions(req.get_extensions())
                cert.add_extensions([
                    crypto.X509Extension(convert_string_to_byte('subjectKeyIdentifier'), False, convert_string_to_byte('hash'), subject=cert),
                    crypto.X509Extension(convert_string_to_byte('keyUsage'), True, convert_string_to_byte('digitalSignature,keyEncipherment')),
                    crypto.X509Extension(convert_string_to_byte('authorityKeyIdentifier'), False, convert_string_to_byte('keyid:always'), issuer=ca_cert),
                    crypto.X509Extension(convert_string_to_byte('basicConstraints'), True, convert_string_to_byte('CA:FALSE')),
                    crypto.X509Extension(convert_string_to_byte('extendedKeyUsage'), False, convert_string_to_byte('serverAuth')),
                ])
                cert.sign(ca_key, 'sha256')
                serial = cert.get_serial_number()
                # save cert if needed
                if self.cert_save_path and self.cert_save_path is not None:
                    # create cert-store dir if not existing
                    if not os.path.isdir(self.cert_save_path):
                        self.logger.debug('create certsavedir {0}'.format(self.cert_save_path))
                        os.mkdir(self.cert_save_path)

                    with open('{0}/{1}.pem'.format(self.cert_save_path, str(serial)), 'wb') as fso:
                        fso.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
                # create bundle and raw cert
                cert_bundle = self._pemcertchain_generate(convert_byte_to_string(crypto.dump_certificate(crypto.FILETYPE_PEM, cert)), open(self.issuer_dict['issuing_ca_cert']).read())
                cert_raw = convert_byte_to_string(base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)))

            except BaseException as err:
                error = err

        self.logger.debug('CAhandler.enroll() ended')
        return(error, cert_bundle, cert_raw, None)

    def revoke(self, cert, rev_reason='unspecified', rev_date=None):
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke({0}: {1})'.format(rev_reason, rev_date))
        code = None
        message = None
        detail = None

        # overwrite revocation date - we ignore what has been submitted
        rev_date = uts_to_date_utc(uts_now(), '%y%m%d%H%M%SZ')

        if 'issuing_ca_crl' in self.issuer_dict and self.issuer_dict['issuing_ca_crl']:
            # load ca cert and key
            (ca_key, ca_cert) = self._ca_load()
            result = self._certificate_chain_verify(cert, ca_cert)
            # proceed if the cert and ca-cert belong together
            if not result:
                serial = cert_serial_get(self.logger, cert)
                # serial = serial.replace('0x', '')
                if ca_key and ca_cert and serial:
                    serial = hex(serial).replace('0x', '')
                    if os.path.exists(self.issuer_dict['issuing_ca_crl']):
                        # existing CRL
                        with open(self.issuer_dict['issuing_ca_crl'], 'r') as fso:
                            crl = crypto.load_crl(crypto.FILETYPE_PEM, fso.read())
                        # check CRL already contains serial
                        sn_match = self._crl_check(crl, serial)
                    else:
                        # new CRL
                        crl = crypto.CRL()
                        sn_match = None

                    # this is the revocation operation
                    if not sn_match:
                        revoked = crypto.Revoked()
                        revoked.set_reason(convert_string_to_byte(rev_reason))
                        revoked.set_serial(convert_string_to_byte(serial))
                        revoked.set_rev_date(convert_string_to_byte(rev_date))
                        crl.add_revoked(revoked)
                        # save CRL
                        crl_text = crl.export(ca_cert, ca_key, crypto.FILETYPE_PEM, 7, convert_string_to_byte('sha256'))
                        with open(self.issuer_dict['issuing_ca_crl'], 'wb') as fso:
                            fso.write(crl_text)
                        code = 200
                    else:
                        code = 400
                        message = 'urn:ietf:params:acme:error:alreadyRevoked'
                        detail = 'Certificate has already been revoked'
                else:
                    code = 400
                    message = 'urn:ietf:params:acme:error:serverInternal'
                    detail = 'configuration error'
            else:
                code = 400
                message = 'urn:ietf:params:acme:error:serverInternal'
                detail = result
        else:
            code = 400
            message = 'urn:ietf:params:acme:error:serverInternal'
            detail = 'Unsupported operation'

        self.logger.debug('CAhandler.revoke() ended')
        return(code, message, detail)
