#!/usr/bin/python
# -*- coding: utf-8 -*-
""" ca handler for  generic cmpv2 """
from __future__ import print_function
import os
import shutil
import subprocess
import tempfile
# pylint: disable=E0401, C0209
from acme_srv.helper import load_config, build_pem_file, b64_url_recode


class CAhandler(object):
    """ EST CA  handler """

    def __init__(self, _debug=None, logger=None):
        self.logger = logger
        self.config_dic = {}
        self.openssl_bin = None
        self.tmp_dir = None
        self.recipient = None
        self.ref = None
        self.secret = None
        self.ca_pubs_file = None
        self.cert_file = None

    def __enter__(self):
        """ Makes CAhandler a Context Manager """
        if not self.openssl_bin:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _certs_bundle(self):
        """ create needed cert(bundle) """
        self.logger.debug('CAhandler._certs_bundle()')

        cert_raw = None
        cert_bundle = None
        ca_pem = None

        if os.path.isfile(self.ca_pubs_file):
            with open(self.ca_pubs_file, 'r', encoding='utf-8') as fso:
                ca_pem = fso.read()

        # open certificate
        if os.path.isfile(self.cert_file):
            with open(self.cert_file, 'r', encoding='utf-8') as fso:
                cert_raw = fso.read()

            # create bundle and raw cert
            if cert_raw and ca_pem:
                cert_bundle = cert_raw + ca_pem
            elif cert_raw:
                cert_bundle = cert_raw
            if cert_raw:
                cert_raw = cert_raw.replace('-----BEGIN CERTIFICATE-----\n', '')
                cert_raw = cert_raw.replace('-----END CERTIFICATE-----\n', '')
                cert_raw = cert_raw.replace('\n', '')
        self.logger.debug('CAhandler._certs_bundle() ended with {0}/{1}'.format(bool(cert_bundle), bool(cert_raw)))
        return (cert_bundle, cert_raw)

    def _config_refsecret_load(self, config_dic):
        """" load ref secrets from file """
        self.logger.debug('CAhandler._config_refsecret_load()')

        if 'CAhandler' in config_dic and 'cmp_ref' in config_dic['CAhandler']:
            if self.ref:
                self.logger.info('CAhandler._config_load() overwrite cmp_ref variable')
            self.ref = config_dic['CAhandler']['cmp_ref']
        if 'CAhandler' in config_dic and 'cmp_secret' in config_dic['CAhandler']:
            if self.secret:
                self.logger.info('CAhandler._config_load() overwrite cmp_secret variable')
            self.secret = config_dic['CAhandler']['cmp_secret']

        self.logger.debug('CAhandler._config_refsecret_load() ended')

    def _config_paramters_load(self):
        """" load refsecrets from file """
        self.logger.debug('CAhandler._config_paramters_load()')

        if 'cmd' not in self.config_dic:
            self.config_dic['cmd'] = 'ir'
        if 'popo' not in self.config_dic:
            self.config_dic['popo'] = 0

        # create temporary directory
        self.tmp_dir = tempfile.mkdtemp()
        self.ca_pubs_file = '{0}/capubs.pem'.format(self.tmp_dir)
        self.cert_file = '{0}/cert.pem'.format(self.tmp_dir)

        # defaulting openssl_bin
        if not self.openssl_bin:
            self.logger.warning('CAhandler config error: "cmp_openssl_bin" parameter not in config_file. Using default (/usr/bin/openssl)')
            self.openssl_bin = '/usr/bin/openssl'

        if not self.recipient:
            self.logger.error('CAhandler config error: "cmp_recipient" is missing in config_file.')

        self.logger.debug('CAhandler._config_paramters_load() ended')

    def _config_cmprecipient_load(self, config_dic):
        """ load and format recipient """
        self.logger.debug('CAhandler._config_cmprecipient_load()')

        if config_dic['CAhandler']['cmp_recipient'].startswith('/'):
            value = config_dic['CAhandler']['cmp_recipient']
        else:
            value = '/' + config_dic['CAhandler']['cmp_recipient']
        value = value.replace(', ', '/')
        value = value.replace(',', '/')
        self.config_dic['recipient'] = value

        self.logger.debug('CAhandler._config_cmprecipient_load() ended')

    def _config_cmpparameter_load(self, ele, config_dic):
        """ load cmp parameters """
        self.logger.debug('CAhandler._config_cmpparameter_load()')

        if ele == 'cmp_openssl_bin':
            self.openssl_bin = config_dic['CAhandler']['cmp_openssl_bin']
        elif ele == 'cmp_recipient':
            self._config_cmprecipient_load(config_dic)
        elif ele == 'cmp_ref_variable':
            try:
                self.ref = os.environ[config_dic['CAhandler']['cmp_ref_variable']]
            except Exception as err:
                self.logger.error('CAhandler._config_load() could not load cmp_ref:{0}'.format(err))
        elif ele == 'cmp_secret_variable':
            try:
                self.secret = os.environ[config_dic['CAhandler']['cmp_secret_variable']]
            except Exception as err:
                self.logger.error('CAhandler._config_load() could not load cmp_secret_variable:{0}'.format(err))
        elif ele in ('cmp_secret', 'cmp_ref'):
            self.logger.debug('CAhandler._config_cmpparameter_load() ignore {0}'.format(ele))
        else:
            if config_dic['CAhandler'][ele] == 'True' or config_dic['CAhandler'][ele] == 'False':
                self.config_dic[ele[4:]] = config_dic.getboolean('CAhandler', ele, fallback=False)
            else:
                self.config_dic[ele[4:]] = config_dic['CAhandler'][ele]

        self.logger.debug('CAhandler._config_cmpparameter_load() ended')

    def _config_load(self):
        """" load config from file """
        # pylint: disable=R0912, R0915
        self.logger.debug('CAhandler._config_load()')
        config_dic = load_config(self.logger, 'CAhandler')

        if 'CAhandler' in config_dic:
            for ele in config_dic['CAhandler']:
                if ele.startswith('cmp_'):
                    self._config_cmpparameter_load(ele, config_dic)

        # load ref/psk information
        self._config_refsecret_load(config_dic)
        # load file and directory names
        self._config_paramters_load()

        self.logger.debug('CAhandler._config_load() ended')

    def _opensslcmd_build(self):
        """ build openssl command """
        self.logger.debug('CAhandler._opensslcmd_build()')

        cmd_list = [self.openssl_bin, 'cmp']
        for ele, value in self.config_dic.items():
            cmd_list.append('-{0}'.format(str(ele)))
            if value is not True:
                cmd_list.append(str(value))

        cmd_list.extend(['-csr', '{0}/csr.pem'.format(self.tmp_dir), '-extracertsout', self.ca_pubs_file, '-certout', self.cert_file])

        # set timeouts if not configured
        if '-msg_timeout' not in cmd_list:
            cmd_list.extend(['-msg_timeout', '5'])
        if '-total_timeout' not in cmd_list:
            cmd_list.extend(['-total_timeout', '10'])

        if self.secret and self.ref:
            cmd_list.extend(['-ref', self.ref])
        if self.secret and self.ref:
            cmd_list.extend(['-secret', self.secret])

        self.logger.debug('CAhandler._opensslcmd_build() ended with: {0}'.format(' '.join(cmd_list)))
        return cmd_list

    def _file_save(self, filename, content):
        """ save content to file """
        self.logger.debug('CAhandler._file_save({0})'.format(filename))
        with open(filename, 'w', encoding='utf-8') as fso:
            fso.write(content)
        self.logger.debug('CAhandler._file_save() ended')

    def _tmp_dir_delete(self):
        """ delete temp files """
        self.logger.debug('CAhandler._tmp_dir_delete({0})'.format(self.tmp_dir))

        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir)
        else:
            self.logger.error('CAhandler._tmp_dir_delete(): failed: {0}'.format(self.tmp_dir))

    def enroll(self, csr):
        """ enroll certificate from via MS certsrv """
        self.logger.debug('CAhandler.enroll()')
        cert_bundle = None
        error = None
        cert_raw = None

        if self.openssl_bin:

            # prepare the CSR to be signed
            csr = build_pem_file(self.logger, None, b64_url_recode(self.logger, csr), None, True)
            # dump csr key
            self._file_save('{0}/csr.pem'.format(self.tmp_dir), csr)

            # build openssl command and run it
            openssl_cmd = self._opensslcmd_build()
            rcode = subprocess.call(openssl_cmd)
            if rcode:
                self.logger.error('CAhandler.enroll(): failed: {0}'.format(rcode))
                error = 'rc from enrollment not 0'

            # generate certificates we need to return
            if os.path.isfile('{0}/cert.pem'.format(self.tmp_dir)):
                (cert_bundle, cert_raw) = self._certs_bundle()
            else:
                error = 'Enrollment failed'

            # delete temporary files
            self._tmp_dir_delete()

        else:
            error = 'Config incomplete'

        self.logger.debug('Certificate.enroll() ended with error: {0}'.format(error))
        return (error, cert_bundle, cert_raw, None)

    def poll(self, _cert_name, poll_identifier, _csr):
        """ poll status of pending CSR and download certificates """
        self.logger.debug('CAhandler.poll()')

        error = 'Method not implemented.'
        cert_bundle = None
        cert_raw = None
        rejected = False

        self.logger.debug('CAhandler.poll() ended')
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(self, _cert, _rev_reason, _rev_date):
        """ revoke certificate """
        self.logger.debug('CAhandler.tsg_id_lookup()')

        # get serial from pem file and convert to formated hex

        code = 500
        message = 'urn:ietf:params:acme:error:serverInternal'
        detail = 'Revocation is not supported.'

        return (code, message, detail)

    def trigger(self, _payload):
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')

        error = 'Method not implemented.'
        cert_bundle = None
        cert_raw = None

        self.logger.debug('CAhandler.trigger() ended with error: {0}'.format(error))
        return (error, cert_bundle, cert_raw)
