#!/usr/bin/python
# -*- coding: utf-8 -*-
""" ca handler for  generic cmpv2 """
from __future__ import print_function
import os
import time
import subprocess
# pylint: disable=E0401
from acme.helper import load_config, csr_dn_get, csr_pubkey_get, csr_san_get

class CAhandler(object):
    """ EST CA  handler """

    def __init__(self, _debug=None, logger=None):
        self.logger = logger
        self.config_dic = {}
        self.openssl_bin = None
        self.tmp_dir = None

    def __enter__(self):
        """ Makes CAhandler a Context Manager """
        if not self.openssl_bin:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _certs_bundle(self, uts):
        """ create needed cert(bundle) """
        self.logger.debug('CAhandler._certs_bundle()')

        cert_raw = None
        cert_bundle = None
        ca_pem = None

        # open ca files
        if os.path.isfile('{0}/{1}_capubs.pem'.format(self.tmp_dir, uts)):
            fso = open('{0}/{1}_capubs.pem'.format(self.tmp_dir, uts), 'r')
            ca_pem = fso.read()
            # fso.close
        # open certificate
        if os.path.isfile('{0}/{1}_cert.pem'.format(self.tmp_dir, uts)):
            fso = open('{0}/{1}_cert.pem'.format(self.tmp_dir, uts), 'r')
            cert_raw = fso.read()
            # fso.close

            # create bundle and raw cert
            cert_bundle = cert_raw + ca_pem
            cert_raw = cert_raw.replace('-----BEGIN CERTIFICATE-----\n', '')
            cert_raw = cert_raw.replace('-----END CERTIFICATE-----\n', '')
            cert_raw = cert_raw.replace('\n', '')

        return(cert_bundle, cert_raw)

    def _csr_san_get(self, csr):
        """ get subAltNames from CSR and format them as needed """
        self.logger.debug('CAhandler._csr_san_get()')
        san_list = csr_san_get(self.logger, csr)

        o_list = []
        for san in san_list:
            (_type, value) = san.lower().split(':')
            if value:
                o_list.append(value)

        sans = '"{0}"'.format(', '.join(o_list))
        self.logger.debug('CAhandler._csr_san_get() ended with: {0}'.format(sans))
        return sans

    def _config_load(self):
        """" load config from file """
        self.logger.debug('CAhandler._config_load()')
        config_dic = load_config(self.logger, 'CAhandler')

        for ele in config_dic['CAhandler']:
            if ele.startswith('cmp_'):
                if ele == 'cmp_openssl_bin':
                    self.openssl_bin = config_dic['CAhandler']['cmp_openssl_bin']
                elif ele == 'cmp_tmp_dir':
                    self.tmp_dir = config_dic['CAhandler']['cmp_tmp_dir']
                elif ele == 'cmp_recipient':
                    if config_dic['CAhandler']['cmp_recipient'].startswith('/'):
                        value = config_dic['CAhandler'][ele]
                    else:
                        value = '/'+config_dic['CAhandler'][ele]
                    value = value.replace(', ', '/')
                    value = value.replace(',', '/')
                    self.config_dic['recipient'] = value
                else:
                    if config_dic['CAhandler'][ele] == 'True' or config_dic['CAhandler'][ele] == 'False':
                        self.config_dic[ele[4:]] = config_dic.getboolean('CAhandler', ele, fallback=False)
                    else:
                        self.config_dic[ele[4:]] = config_dic['CAhandler'][ele]

        if 'cmd' not in self.config_dic:
            self.config_dic['cmd'] = 'ir'
        if 'popo' not in self.config_dic:
            self.config_dic['popo'] = 0

        # create temp dir if needed
        if not os.path.exists(self.tmp_dir):
            os.makedirs(self.tmp_dir)

        self.logger.debug('CAhandler._config_load() ended')

    def _opensslcmd_build(self, uts, subject, san_list):
        """ build openssl command """
        self.logger.debug('CAhandler._opensslcmd_build()')

        cmd_list = [self.openssl_bin, 'cmp']
        for ele in self.config_dic:
            cmd_list.append('-{0}'.format(str(ele)))
            if not self.config_dic[ele] is True:
                cmd_list.append(str(self.config_dic[ele]))

        # add additonal parameters to openssl_cmd
        cmd_list.extend(['-subject', subject, '-newkey', '{0}/{1}_pubkey.pem'.format(self.tmp_dir, uts)])
        if san_list:
            cmd_list.extend(['-sans', san_list])
        cmd_list.extend(['-extracertsout', '{0}/{1}_capubs.pem'.format(self.tmp_dir, uts), '-certout', '{0}/{1}_cert.pem'.format(self.tmp_dir, uts)])

        # set timeouts if not configured
        if '-msgtimeout' not in cmd_list:
            cmd_list.extend(['-msgtimeout', '5'])
        if '-totaltimeout' not in cmd_list:
            cmd_list.extend(['-totaltimeout', '10'])

        self.logger.debug('CAhandler._opensslcmd_build() ended with: {0}'.format(' '.join(cmd_list)))
        return cmd_list

    def _pubkey_save(self, uts, pubkey):
        """ save public key to file """
        self.logger.debug('CAhandler._pubkey_save()')
        with open('{0}/{1}_pubkey.pem'.format(self.tmp_dir, str(uts)), 'w') as fso:
            fso.write(pubkey)
        self.logger.debug('CAhandler._pubkey_save() ended')


    def _tmp_files_delete(self, uts):
        """ delete temp files """
        self.logger.debug('CAhandler._tmp_files_delete({0})'.format(uts))

        if os.path.isfile('{0}/{1}_cert.pem'.format(self.tmp_dir, uts)):
            os.remove('{0}/{1}_cert.pem'.format(self.tmp_dir, uts))
            self.logger.debug('CAhandler._tmp_files_delete() cert')
        if os.path.isfile('{0}/{1}_pubkey.pem'.format(self.tmp_dir, uts)):
            os.remove('{0}/{1}_pubkey.pem'.format(self.tmp_dir, uts))
            self.logger.debug('CAhandler._tmp_files_delete() pubkey')
        if os.path.isfile('{0}/{1}_capubs.pem'.format(self.tmp_dir, uts)):
            os.remove('{0}/{1}_capubs.pem'.format(self.tmp_dir, uts))
            self.logger.debug('CAhandler._tmp_files_delete() capub')

    def enroll(self, csr):
        """ enroll certificate from via MS certsrv """
        self.logger.debug('CAhandler.enroll()')
        cert_bundle = None
        error = None
        cert_raw = None

        if self.openssl_bin:
            # get unix time stamp
            uts = str(int(time.time()))
            # get subject
            try:
                subject = csr_dn_get(self.logger, csr)
                if not subject:
                    subject = '/CN=acme2certifier'
            except BaseException:
                subject = None
            # get public key from csr
            try:
                pubkey = csr_pubkey_get(self.logger, csr)
            except BaseException:
                pubkey = None
            # get subject alternate names
            try:
                san_list = self._csr_san_get(csr)
            except BaseException:
                san_list = []

            if subject and pubkey and san_list:
                # dump public key
                self._pubkey_save(uts, pubkey)

                # build openssl command and run it
                openssl_cmd = self._opensslcmd_build(uts, subject, san_list)
                subprocess.call(openssl_cmd)

                # generate certificates we need to return
                if os.path.isfile('{0}/{1}_cert.pem'.format(self.tmp_dir, uts)):
                    (cert_bundle, cert_raw) = self._certs_bundle(uts)
                else:
                    error = 'Enrollment failed'

                # delete temporary files
                self._tmp_files_delete(uts)
            else:
                error = 'CSR invalid'
        else:
            error = 'Config incomplete'

        self.logger.debug('Certificate.enroll() ended')
        return(error, cert_bundle, cert_raw, None)

    def revoke(self, _cert, _rev_reason, _rev_date):
        """ revoke certificate """
        self.logger.debug('CAhandler.tsg_id_lookup()')
        # get serial from pem file and convert to formated hex

        code = 500
        message = 'urn:ietf:params:acme:error:serverInternal'
        detail = 'Revocation is not supported.'

        return(code, message, detail)
