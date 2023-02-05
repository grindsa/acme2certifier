# -*- coding: utf-8 -*-
""" ejbca rest ca handler """
import requests
# pylint: disable=C0209, E0401
from acme_srv.helper import load_config, build_pem_file, cert_pem2der, b64_url_recode, b64_encode, cert_serial_get, cert_issuer_get


class CAhandler(object):
    """ ejbca rest handler class """

    def __init__(self, _debug=None, logger=None):
        self.logger = logger
        self.host = None
        self.ca_bundle = True
        self.proxy = None
        self.request_timeout = 5
        self.cert_profile_name = None
        self.client_cert = None
        self.endpoint_name = None

    def __enter__(self):
        """ Makes CAhandler a Context Manager """
        if not self.host:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _cert_bundle_create(self, response):
        """ format bundle """
        error = None
        cert_bundle = None
        cert_raw = None

        if 'data' in response and 'certificate' in response['data'] and 'chain' in response['data']:
            # create base65 encoded der file
            cert_raw = b64_encode(self.logger, cert_pem2der(response['data']['certificate']))
            cert_bundle = '{0}{1}'.format(response['data']['certificate'], response['data']['chain'])
        else:
            error = 'Malformed response'
            self.logger.error('CAhandler._cert_bundle_create() returned malformed response: {0}'.format(response))

        return (error, cert_bundle, cert_raw)

    def _config_server_load(self, config_dic):
        """ load server information """
        self.logger.debug('CAhandler._config_auth_load()')

        if 'CAhandler' in config_dic and 'host' in config_dic['CAhandler']:
            self.host = config_dic['CAhandler']['host']

        if 'CAhandler' in config_dic and 'endpoint_name' in config_dic['CAhandler']:
            self.endpoint_name = config_dic['CAhandler']['endpoint_name']

        if 'CAhandler' in config_dic and 'request_timeout' in config_dic['CAhandler']:
            self.request_timeout = config_dic['CAhandler']['request_timeout']

        if 'CAhandler' in config_dic and 'ca_bundle' in config_dic['CAhandler']:
            try:
                self.ca_bundle = config_dic.getboolean('CAhandler', 'ca_bundle')
            except Exception:
                self.ca_bundle = config_dic['CAhandler']['ca_bundle']

        if 'CAhandler' in config_dic and 'cert_profile_name' in config_dic['CAhandler']:
            self.cert_profile_name = config_dic['CAhandler']['cert_profile_name']

        self.logger.debug('CAhandler._config_server_load() ended')

    def _config_clientauth_load(self, config_dic):
        """ check if we need to use clientauth """
        self.logger.debug('CAhandler._config_clientauth_load()')

        if 'client_cert' in config_dic['CAhandler'] and 'client_key' in config_dic['CAhandler']:
            self.client_cert = []
            self.client_cert.append(config_dic['CAhandler']['client_cert'])
            self.client_cert.append(config_dic['CAhandler']['client_key'])
        elif 'client_cert' in config_dic['CAhandler'] or 'client_key' in config_dic['CAhandler']:
            self.logger.error('CAhandler._config_load() configuration incomplete: either "client_cert or "client_key" parameter is missing in config file')

        self.logger.debug('CAhandler._config_clientauth_load() ended')

    def _config_load(self):
        """" load config from file """
        self.logger.debug('CAhandler._config_load()')

        config_dic = load_config(self.logger, 'CAhandler')

        # load configuration
        self._config_server_load(config_dic)
        self._config_clientauth_load(config_dic)

        # check configuration for completeness
        variable_dic = self.__dict__
        for ele in ['host', 'cert_profile_name', 'client_cert', 'endpoint_name']:
            if not variable_dic[ele]:
                self.logger.error('CAhandler._config_load(): configuration incomplete: parameter "{0}" is missing in configuration file.'.format(ele))
        self.logger.debug('CAhandler._config_load() ended')

    def _rpc_post(self, path, data_dic):
        """ enrollment via post request to openxpki RPC interface """
        self.logger.debug('CAhandler.enroll()')
        try:
            # enroll via rpc
            response = requests.post(self.host + path, data=data_dic, cert=self.client_cert, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()
        except Exception as err_:
            self.logger.error('CAhandler.enroll() returned an error: {0}'.format(err_))
            response = {}

        self.logger.debug('CAhandler.enroll() ended.')
        return response

    def enroll(self, csr):
        """ enroll certificate  """
        self.logger.debug('CAhandler.enroll()')

        cert_bundle = None
        error = None
        cert_raw = None
        poll_indentifier = None

        if self.host:

            # prepare the CSR to be signed
            csr = build_pem_file(self.logger, None, b64_url_recode(self.logger, csr), None, True)

            data_dic = {
                'method': 'RequestCertificate',
                'comment': 'acme2certifier',
                'pkcs10': csr,
                'profile': self.cert_profile_name
            }
            if self.client_cert:

                sign_response = self._rpc_post('/rpc/' + self.endpoint_name, data_dic)

                if 'result' in sign_response and 'state' in sign_response['result'] and sign_response['result']['state'].upper() == 'SUCCESS':
                    (error, cert_bundle, cert_raw) = self._cert_bundle_create(sign_response['result'])
                else:
                    error = 'Malformed response'
                    self.logger.error('CAhandler.enroll(): Malformed Rest response: {0}'.format(sign_response))

        self.logger.debug('Certificate.enroll() ended')
        return (error, cert_bundle, cert_raw, poll_indentifier)

    def poll(self, _cert_name, poll_identifier, _csr):
        """ poll status of pending CSR and download certificates """
        self.logger.debug('CAhandler.poll()')

        error = 'Method not implemented.'
        cert_bundle = None
        cert_raw = None
        rejected = False

        self.logger.debug('CAhandler.poll() ended')
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(self, cert, rev_reason='UNSPECIFIED', rev_date=None):
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke({0}: {1})'.format(rev_reason, rev_date))
        code = None
        message = None
        detail = None

        # get cert serial number and issuerdn
        cert_serial = cert_serial_get(self.logger, cert, hexformat=True)
        _issuer_dn = cert_issuer_get(self.logger, cert)

        if 'revoked' in cert_serial:
            pass
        else:
            code = 400
            message = 'urn:ietf:params:acme:error:serverInternal'
            detail = 'Unknown status'

        self.logger.debug('Certificate.revoke() ended')
        return (code, message, detail)

    def trigger(self, _payload):
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')

        error = 'Method not implemented.'
        cert_bundle = None
        cert_raw = None

        self.logger.debug('CAhandler.trigger() ended with error: {0}'.format(error))
        return (error, cert_bundle, cert_raw)
