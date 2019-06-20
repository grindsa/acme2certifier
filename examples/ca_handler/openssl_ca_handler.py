#!/usr/bin/python
# -*- coding: utf-8 -*-
""" ca hanlder for Insta Certifier via REST-API class """
from __future__ import print_function
import os
import json
import base64
from OpenSSL import crypto
from acme.helper import load_config, build_pem_file, uts_now, uts_to_date_utc, b64_url_recode

class CAhandler(object):
    """ CA  handler """

    def __init__(self, debug=None, logger=None):
        self.debug = debug
        self.logger = logger
        self.issuer_dict = {
            'key' : None,
            'cert' : None,
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
        if not os.path.exists(self.issuer_dict['key']):
            error = 'signing key {0} does not exist'.format(self.issuer_dict['ca_key'])
        if not os.path.exists(self.issuer_dict['cert']):
            error = 'signing cert {0} does not exist'.format(self.issuer_dict['ca_cert'])
        if not os.path.exists(self.cert_save_path):
            error = 'cert save path {0} does not exist'.format(self.cert_save_path)
        self.logger.debug('CAhandler.check_config() ended with: {0}'.format(error))
        return error

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
                print(csr)
                if 'passphrase' in self.issuer_dict:
                    self.issuer_dict['passphrase'] = self.issuer_dict['passphrase'].encode('ascii')
                # open key and cert
                ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(self.issuer_dict['key']).read(), self.issuer_dict['passphrase'])
                ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(self.issuer_dict['cert']).read())

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
                cert.sign(ca_key, 'sha256')
                serial = cert.get_serial_number()
                # save cert if needed
                if self.cert_save_path:
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

    def load_config(self):
        """" load config from file """
        self.logger.debug('load_config()')
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

        self.logger.debug('CAhandler.load_config() ended')

    def revoke(self, _cert, rev_reason='unspecified', rev_date=uts_to_date_utc(uts_now())):
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke({0}: {1})'.format(rev_reason, rev_date))
        code = None
        message = None
        detail = None
        return(code, message, detail)
