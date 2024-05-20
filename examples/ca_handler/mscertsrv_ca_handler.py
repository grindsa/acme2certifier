# -*- coding: utf-8 -*-
""" ca handler for  Microsoft Webenrollment service (certsrv) """
from __future__ import print_function
import os
import textwrap
import json
from typing import List, Tuple, Dict
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization.pkcs7 import load_pem_pkcs7_certificates, load_der_pkcs7_certificates
# pylint: disable=e0401, e0611
from examples.ca_handler.certsrv import Certsrv
from acme_srv.helper import load_config, b64_url_recode, convert_byte_to_string, proxy_check, convert_string_to_byte, header_info_get, allowed_domainlist_check  # pylint: disable=e0401


class CAhandler(object):
    """ EST CA  handler """

    def __init__(self, _debug: bool = False, logger: object = None):
        self.logger = logger
        self.host = None
        self.user = None
        self.password = None
        self.auth_method = 'basic'
        self.ca_bundle = False
        self.template = None
        self.krb5_config = None
        self.proxy = None
        self.allowed_domainlist = []
        self.header_info_field = False
        self.verify = True

    def __enter__(self):
        """ Makes CAhandler a Context Manager """
        if not self.host:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _check_credentials(self, ca_server: str) -> bool:
        """ check creadentials """
        self.logger.debug('CAhandler.__check_credentials()')
        auth_check = ca_server.check_credentials()
        self.logger.debug('CAhandler.__check_credentials() ended with %s', auth_check)
        return auth_check

    def _cert_bundle_create(self, ca_pem: str = None, cert_raw: str = None) -> Tuple[str, str, str]:
        """ create bundle """
        self.logger.debug('CAhandler._cert_bundle_create()')

        error = None
        cert_bundle = None

        if ca_pem and cert_raw:
            cert_bundle = cert_raw + ca_pem
            cert_raw = cert_raw.replace('-----BEGIN CERTIFICATE-----\n', '')
            cert_raw = cert_raw.replace('-----END CERTIFICATE-----\n', '')
            cert_raw = cert_raw.replace('\n', '')
        else:
            self.logger.error('cert bundling failed')
            error = 'cert bundling failed'

        return (error, cert_bundle, cert_raw)

    def _config_headerinfo_load(self, config_dic: Dict[str, str]):
        """ load parameters """
        self.logger.debug('_config_header_info()')

        if 'Order' in config_dic and 'header_info_list' in config_dic['Order'] and config_dic['Order']['header_info_list']:
            try:
                self.header_info_field = json.loads(config_dic['Order']['header_info_list'])[0]
            except Exception as err_:
                self.logger.warning('Order._config_orderconfig_load() header_info_list failed with error: %s', err_)

        self.logger.debug('_config_header_info() ended')

    def _config_user_load(self, config_dic: Dict[str, str]):
        """ load username """
        self.logger.debug('CAhandler._config_user_load()')

        if 'user_variable' in config_dic['CAhandler']:
            try:
                self.user = os.environ[config_dic['CAhandler']['user_variable']]
            except Exception as err:
                self.logger.error('CAhandler._config_load() could not load user_variable:%s', err)
        if 'user' in config_dic['CAhandler']:
            if self.user:
                self.logger.info('CAhandler._config_load() overwrite user')
            self.user = config_dic['CAhandler']['user']

        self.logger.debug('CAhandler._config_user_load() ended')

    def _config_password_load(self, config_dic: Dict[str, str]):
        """ load username """
        self.logger.debug('CAhandler._config_password_load()')

        if 'password_variable' in config_dic['CAhandler']:
            try:
                self.password = os.environ[config_dic['CAhandler']['password_variable']]
            except Exception as err:
                self.logger.error('CAhandler._config_load() could not load password_variable:%s', err)
        if 'password' in config_dic['CAhandler']:
            if self.password:
                self.logger.info('CAhandler._config_load() overwrite password')
            self.password = config_dic['CAhandler']['password']

        self.logger.debug('CAhandler._config_password_load() ended')

    def _config_hostname_load(self, config_dic: Dict[str, str]):
        """ load hostname """
        self.logger.debug('CAhandler._config_hostname_load()')

        if 'host_variable' in config_dic['CAhandler']:
            try:
                self.host = os.environ[config_dic['CAhandler']['host_variable']]
            except Exception as err:
                self.logger.error('CAhandler._config_load() could not load host_variable:%s', err)
        if 'host' in config_dic['CAhandler']:
            if self.host:
                self.logger.info('CAhandler._config_load() overwrite host')
            self.host = config_dic['CAhandler']['host']

        self.logger.debug('CAhandler._config_hostname_load() ended')

    def _config_parameters_load(self, config_dic: Dict[str, str]):
        """ load hostname """
        self.logger.debug('CAhandler._config_parameters_load()')

        if 'template' in config_dic['CAhandler']:
            self.template = config_dic['CAhandler']['template']
        if 'auth_method' in config_dic['CAhandler'] and config_dic['CAhandler']['auth_method'] in ['basic', 'ntlm', 'gssapi']:
            self.auth_method = config_dic['CAhandler']['auth_method']
        # check if we get a ca bundle for verification
        if 'ca_bundle' in config_dic['CAhandler']:
            self.ca_bundle = config_dic['CAhandler']['ca_bundle']
        if 'krb5_config' in config_dic['CAhandler']:
            self.krb5_config = config_dic['CAhandler']['krb5_config']

        self.verify = config_dic.getboolean('CAhandler', 'verify', fallback=True)

        if 'allowed_domainlist' in config_dic['CAhandler']:
            try:
                self.allowed_domainlist = json.loads(config_dic['CAhandler']['allowed_domainlist'])
            except Exception as err:
                self.logger.error('CAhandler._config_load(): failed to parse allowed_domainlist: %s', err)
                self.allowed_domainlist = 'ADLFAILURE'

        self.logger.debug('CAhandler._config_parameters_load() ended')

    def _config_proxy_load(self, config_dic: Dict[str, str]):
        """ load hostname """
        self.logger.debug('CAhandler._config_proxy_load()')

        if 'DEFAULT' in config_dic and 'proxy_server_list' in config_dic['DEFAULT']:
            try:
                proxy_list = json.loads(config_dic['DEFAULT']['proxy_server_list'])
                proxy_server = proxy_check(self.logger, self.host, proxy_list)
                self.proxy = {'http': proxy_server, 'https': proxy_server}
            except Exception as err_:
                self.logger.warning('CAhandler._config_load() proxy_server_list failed with error: %s', err_)

        self.logger.debug('CAhandler._config_proxy_load() ended')

    def _config_load(self):
        """" load config from file """
        self.logger.debug('CAhandler._config_load()')
        config_dic = load_config(self.logger, 'CAhandler')

        if 'CAhandler' in config_dic:
            # load parameters from config dic
            self._config_hostname_load(config_dic)
            self._config_user_load(config_dic)
            self._config_password_load(config_dic)
            self._config_parameters_load(config_dic)
            self._config_headerinfo_load(config_dic)

        # load proxy config
        self._config_proxy_load(config_dic)

        self.logger.debug('CAhandler._config_load() ended')

    def _pkcs7_to_pem(self, pkcs7_content: str, outform: str = 'string') -> List[str]:
        """ convert pkcs7 to pem """
        self.logger.debug('CAhandler._pkcs7_to_pem()')

        try:
            pkcs7_obj = load_pem_pkcs7_certificates(convert_string_to_byte(pkcs7_content))
        except Exception:
            self.logger.debug('CAhandler._pkcs7_to_pem(): load pem failed. Try der...')
            pkcs7_obj = load_der_pkcs7_certificates(pkcs7_content)

        cert_pem_list = []
        for cert in pkcs7_obj:
            cert_pem_list.append(convert_byte_to_string(cert.public_bytes(serialization.Encoding.PEM)))

        # define output format
        if outform == 'string':
            result = ''.join(cert_pem_list)
        elif outform == 'list':
            result = cert_pem_list
        else:
            result = None

        self.logger.debug('Certificate._pkcs7_to_pem() ended')
        return result

    def _template_name_get(self, csr: str) -> str:
        """ get templaate from csr """
        self.logger.debug('CAhandler._template_name_get(%s)', csr)
        template_name = None

        # parse profileid from http_header
        header_info = header_info_get(self.logger, csr=csr)
        if header_info:
            try:
                header_info_dic = json.loads(header_info[-1]['header_info'])
                if self.header_info_field in header_info_dic:
                    for ele in header_info_dic[self.header_info_field].split(' '):
                        if 'template' in ele.lower():
                            template_name = ele.split('=')[1]
                            break
            except Exception as err:
                self.logger.error('CAhandler._template_name_get() could not parse template: %s', err)

        self.logger.debug('CAhandler._template_name_get() ended with: %s', template_name)
        return template_name

    def _csr_process(self, ca_server, csr: str) -> Tuple[str, str, str]:

        # recode csr
        csr = textwrap.fill(b64_url_recode(self.logger, csr), 64) + '\n'

        # get ca_chain
        try:
            ca_pkcs7 = convert_byte_to_string(ca_server.get_chain(encoding='b64'))
            ca_pem = self._pkcs7_to_pem(ca_pkcs7)
            # replace crlf with lf
            # ca_pem = ca_pem.replace('\r\n', '\n')
        except Exception as err_:
            ca_pem = None
            self.logger.error('ca_server.get_chain() failed with error: %s', err_)

        try:
            cert_p2b = ca_server.get_cert(csr, self.template)
            cert_raw = convert_byte_to_string(cert_p2b)
            # replace crlf with lf
            cert_raw = cert_raw.replace('\r\n', '\n')
        except Exception as err_:
            cert_raw = None
            error = str(err_)
            self.logger.error('ca_server.get_cert() failed with error: %s', err_)

        # create bundle
        if cert_raw:
            (error, cert_bundle, cert_raw) = self._cert_bundle_create(ca_pem, cert_raw)
        else:
            cert_bundle = None

        return (error, cert_bundle, cert_raw)

    def _parameter_overwrite(self, csr: str):
        """ overwrite overwrite krb5.conf or user-template """
        if self.krb5_config:
            self.logger.info('CAhandler.enroll(): load krb5config from %s', self.krb5_config)
            os.environ['KRB5_CONFIG'] = self.krb5_config

        # lookup http header information from request
        if self.header_info_field:
            user_template = self._template_name_get(csr)
            if user_template:
                self.template = user_template

    def _domainlist_check(self, csr: str) -> bool:
        """ check if domain is in allowed domainlist """
        self.logger.debug('CAhandler._domainlist_check()')

        if self.allowed_domainlist:
            if self.allowed_domainlist != 'ADLFAILURE':
                # check sans / cn against list of allowed comains from config
                result = allowed_domainlist_check(self.logger, csr, self.allowed_domainlist)
            else:
                result = False
        else:
            result = True

        self.logger.debug('CAhandler._domainlist_check() ended with: %s', result)
        return result

    def enroll(self, csr: str) -> Tuple[str, str, str, bool]:
        """ enroll certificate from via MS certsrv """
        self.logger.debug('CAhandler.enroll(%s)', self.template)
        cert_bundle = None
        error = None
        cert_raw = None

        self._parameter_overwrite(csr)

        if self.host and self.user and self.password and self.template:

            result = self._domainlist_check(csr)

            if result:
                # setup certserv
                ca_server = Certsrv(self.host, self.user, self.password, self.auth_method, self.ca_bundle, verify=self.verify, proxies=self.proxy)

                # check connection and credentials
                auth_check = self._check_credentials(ca_server)

                if auth_check:

                    # enroll certificate
                    (error, cert_bundle, cert_raw) = self._csr_process(ca_server, csr)

                else:
                    self.logger.error('Connection or Credentialcheck failed')
                    error = 'Connection or Credentialcheck failed.'
            else:
                self.logger.error('SAN/CN check failed')
                error = 'SAN/CN check failed'
        else:
            self.logger.error('Config incomplete')
            error = 'Config incomplete'

        self.logger.debug('Certificate.enroll() ended')
        return (error, cert_bundle, cert_raw, None)

    def poll(self, _cert_name: str, poll_identifier: str, _csr: str) -> Tuple[str, str, str, str, bool]:
        """ poll status of pending CSR and download certificates """
        self.logger.debug('CAhandler.poll()')

        error = 'Method not implemented.'
        cert_bundle = None
        cert_raw = None
        rejected = False

        self.logger.debug('CAhandler.poll() ended')
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(self, _cert: str, _rev_reason: str, _rev_date: str) -> Tuple[int, str, str]:
        """ revoke certificate """
        self.logger.debug('CAhandler.tsg_id_lookup()')
        # get serial from pem file and convert to formated hex

        code = 500
        message = 'urn:ietf:params:acme:error:serverInternal'
        detail = 'Revocation is not supported.'

        return (code, message, detail)

    def trigger(self, _payload: str) -> Tuple[int, str, str]:
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')

        error = 'Method not implemented.'
        cert_bundle = None
        cert_raw = None

        self.logger.debug('CAhandler.trigger() ended with error: %s', error)
        return (error, cert_bundle, cert_raw)
