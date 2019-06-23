#!/usr/bin/python
# -*- coding: utf-8 -*-
""" ca hanlder for Insta Certifier via REST-API class """
from __future__ import print_function
import os
import json
import base64
from OpenSSL import crypto
from acme.helper import load_config, build_pem_file, uts_now, uts_to_date_utc, b64_url_recode, cert_serial_get

class CAhandler(object):
    """ CA  handler """

    def __init__(self, debug=None, logger=None):
        self.debug = debug
        self.logger = logger
        self.issuer_dict = {
            'key' : None,
            'cert' : None,
            'crl'  : None,
        }
        self.ca_cert_chain_list = []
        self.cert_validity_days = 365
        self.cert_save_path = None

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        if not self.issuer_dict['key']:
            self.load_config()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def check_config(self):
        """ check config for consitency """
        self.logger.debug('CAhandler.check_config()')
        error = None
        if 'key' in self.issuer_dict:
            if not os.path.exists(self.issuer_dict['key']):
                error = 'signing key {0} does not exist'.format(self.issuer_dict['key'])
        else:
            error = 'key "key" does not exist in config_hash'

        if not error:
            if 'cert' in self.issuer_dict:
                if not os.path.exists(self.issuer_dict['cert']):
                    error = 'signing cert {0} does not exist'.format(self.issuer_dict['cert'])
            else:
                error = 'key "cert" does not exist in config_hash'
        return error

    def check_serial_against_crl(self, crl, serial):
        """ check if CRL already contains serial """
        self.logger.debug('CAhandler.check_serial_against_crl()')
        sn_match = False
        for rev in crl.get_revoked():
            if serial == rev.get_serial().lower():
                sn_match = True
                break
        self.logger.debug('CAhandler.check_serial_against_crl() with:{0}'.format(sn_match))
        return sn_match

    def enroll(self, csr):
        """ enroll certificate """
        self.logger.debug('CAhandler.enroll()')

        cert_bundle = None
        cert_raw = None

        error = self.check_config()

        if not error:
            try:
                # prepare the CSR
                csr = build_pem_file(self.logger, None, b64_url_recode(self.logger, csr), None, True)

                # load ca cert and key
                (ca_key, ca_cert) = self.load_ca_key_cert()

                # creating a rest form CSR
                req = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)
                # sign csr
                cert = crypto.X509()
                cert.gmtime_adj_notBefore(0)
                cert.gmtime_adj_notAfter(self.cert_validity_days * 86400)
                cert.set_issuer(ca_cert.get_subject())
                cert.set_subject(req.get_subject())
                cert.set_pubkey(req.get_pubkey())
                cert.set_serial_number(uts_now())
                cert.add_extensions(req.get_extensions())
                cert.add_extensions([
                    crypto.X509Extension("authorityKeyIdentifier", False, "keyid:always", issuer=ca_cert),
                    crypto.X509Extension("extendedKeyUsage", False, "clientAuth"),
                ])
                cert.sign(ca_key, 'sha256')
                serial = cert.get_serial_number()
                # save cert if needed
                if self.cert_save_path and self.cert_save_path != None:
                    # create cert-store dir if not existing
                    if not os.path.isdir(self.cert_save_path):
                        self.logger.debug('create certsavedir {0}'.format(self.cert_save_path))
                        os.mkdir(self.cert_save_path)

                    with open('{0}/{1}.pem'.format(self.cert_save_path, str(serial)), 'wb') as fso:
                        fso.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
                # create bundle and raw cert
                cert_bundle = self.generate_pem_cert_chain(crypto.dump_certificate(crypto.FILETYPE_PEM, cert), open(self.issuer_dict['cert']).read())
                cert_raw = base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_ASN1, cert))

            except BaseException as err:
                error = err

        self.logger.debug('Certificate.enroll() ended')
        return(error, cert_bundle, cert_raw)

    def generate_pem_cert_chain(self, ee_cert, issuer_cert):
        """ build pem chain """
        self.logger.debug('CAhandler.enroll()')

        pem_chain = '{0}{1}'.format(ee_cert, issuer_cert)
        for cert in self.ca_cert_chain_list:
            pem_chain = '{0}{1}'.format(pem_chain, open(cert).read())

        self.logger.debug('CAhandler.enroll() ended')
        return pem_chain

    def load_ca_key_cert(self):
        """ load ca key and cert """
        self.logger.debug('CAhandler.load_ca_key_cert()')
        # open key and cert
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(self.issuer_dict['key']).read(), self.issuer_dict['passphrase'])
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(self.issuer_dict['cert']).read())
        self.logger.debug('CAhandler.load_ca_key_cert() endet')
        return(ca_key, ca_cert)

    def load_config(self):
        """" load config from file """
        self.logger.debug('CAhandler.load_config()')
        config_dic = load_config(self.logger, 'CAhandler')

        if 'issuing_ca_key' in config_dic['CAhandler']:
            self.issuer_dict['key'] = config_dic['CAhandler']['issuing_ca_key']
        if 'issuing_ca_cert' in config_dic['CAhandler']:
            self.issuer_dict['cert'] = config_dic['CAhandler']['issuing_ca_cert']
        if 'issuing_ca_key_passphrase' in config_dic['CAhandler']:
            self.issuer_dict['passphrase'] = config_dic['CAhandler']['issuing_ca_key_passphrase']
        if 'ca_cert_chain_list' in config_dic['CAhandler']:
            self.ca_cert_chain_list = json.loads(config_dic['CAhandler']['ca_cert_chain_list'])
        if 'cert_validity_days' in config_dic['CAhandler']:
            self.cert_validity_days = int(config_dic['CAhandler']['cert_validity_days'])
        if 'cert_save_path' in config_dic['CAhandler']:
            self.cert_save_path = config_dic['CAhandler']['cert_save_path']
        if 'issuing_ca_crl' in config_dic['CAhandler']:
            self.issuer_dict['crl'] = config_dic['CAhandler']['issuing_ca_crl']

        # convert passphrase
        if 'passphrase' in self.issuer_dict:
            self.issuer_dict['passphrase'] = self.issuer_dict['passphrase'].encode('ascii')

        self.logger.debug('CAhandler.load_config() ended')


    def revoke(self, cert, rev_reason='unspecified', rev_date=None):
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke({0}: {1})'.format(rev_reason, rev_date))
        code = None
        message = None
        detail = None

        # overwrite revocation date - we ignore what has been submitted
        rev_date = uts_to_date_utc(uts_now(), '%y%m%d%H%M%SZ')

        if 'crl' in self.issuer_dict and self.issuer_dict['crl']:
            # load ca cert and key
            (ca_key, ca_cert) = self.load_ca_key_cert()
            result = self.verify_certificate_chain(cert, ca_cert)

            # proceed if the cert and ca-cert belong together
            if not result:
                serial = hex(cert_serial_get(self.logger, cert))
                serial = serial.replace('0x', '')
                if ca_key and ca_cert and serial:
                    if os.path.exists(self.issuer_dict['crl']):
                        # existing CRL
                        with open(self.issuer_dict['crl'], 'r') as fso:
                            crl = crypto.load_crl(crypto.FILETYPE_PEM, fso.read())
                        # check CRL already contains serial
                        sn_match = self.check_serial_against_crl(crl, serial)
                    else:
                        # new CRL
                        crl = crypto.CRL()
                        sn_match = None

                    # this is the revocation operation
                    if not sn_match:
                        revoked = crypto.Revoked()
                        revoked.set_reason(rev_reason)
                        revoked.set_serial(serial)
                        revoked.set_rev_date(rev_date)
                        crl.add_revoked(revoked)
                        # save CRL
                        crl_text = crl.export(ca_cert, ca_key, crypto.FILETYPE_PEM, 7, 'sha256')
                        with open(self.issuer_dict['crl'], 'wb') as fso:
                            fso.write(crl_text)

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

    def verify_certificate_chain(self, cert, ca_cert):
        """ verify certificate chain """
        self.logger.debug('CAhandler.verify_certificate_chain()')

        pem_file = build_pem_file(self.logger, None, b64_url_recode(self.logger, cert), True)
        # try:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_file)
        #Create a certificate store and add ca cert(s)
        store = crypto.X509Store()
        store.add_cert(ca_cert)

        # add ca chain to truststore
        for cert_name in self.ca_cert_chain_list:
            cain_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(cert_name).read())
            store.add_cert(cain_cert)

        # Create a certificate context using the store and the downloaded certificate
        store_ctx = crypto.X509StoreContext(store, cert)
        # Verify the certificate, returns None if it can validate the certificate
        result = store_ctx.verify_certificate()
        # except BaseException as err:
        #    result = str(err)

        self.logger.debug('CAhandler.verify_certificate_chain() ended with {0}'.format(result))
        return result
