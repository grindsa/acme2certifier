# -*- coding: utf-8 -*-
""" ejbca rest handler """
import requests
from requests_pkcs12 import Pkcs12Adapter
# pylint: disable=C0209, E0401
from acme_srv.helper import load_config, build_pem_file, b64_url_recode, cert_der2pem, b64_decode, convert_byte_to_string, cert_serial_get, cert_issuer_get, encode_url


class CAhandler(object):
    """ ejbca rest handler class """

    def __init__(self, _debug=None, logger=None):
        self.logger = logger
        self.api_host = None
        self.ca_bundle = True
        self.proxy = None
        self.request_timeout = 5
        self.cert_profile_name = None
        self.ee_profile_name = None
        self.ca_name = None
        self.session = None
        self.username = None
        self.enrollment_code = None

    def __enter__(self):
        """ Makes CAhandler a Context Manager """
        if not self.api_host:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _cert_status_check(self, issuer_dn, cert_serial):
        """ check certificate status """
        self.logger.debug('CAhandler._cert_status_check({0}: {1})'.format(issuer_dn, cert_serial))

        # define path
        path = "/ejbca/ejbca-rest-api/v1/certificate/{0}/{1}/revocationstatus".format(encode_url(self.logger, issuer_dn), cert_serial)

        if self.api_host:
            try:
                certstatus_response = self.session.get(self.api_host + path, proxies=self.proxy, verify=self.ca_bundle, timeout=self.request_timeout).json()
            except Exception as err_:
                self.logger.error('CAhandler._ca_get() returned error: {0}'.format(str(err_)))
                certstatus_response = {'status': 'nok', 'error': str(err_)}
        else:
            self.logger.error('CAhandler._status_get(): api_host is misisng in configuration')
            certstatus_response = {}

        return certstatus_response

    def _config_server_load(self, config_dic):
        """ load server information """
        self.logger.debug('CAhandler._config_auth_load()')

        if 'CAhandler' in config_dic and 'api_host' in config_dic['CAhandler']:
            self.api_host = config_dic['CAhandler']['api_host']

        if 'CAhandler' in config_dic and 'request_timeout' in config_dic['CAhandler']:
            self.request_timeout = config_dic['CAhandler']['request_timeout']

        if 'CAhandler' in config_dic and 'ca_bundle' in config_dic['CAhandler']:
            self.ca_bundle = config_dic['CAhandler']['ca_bundle']

        self.logger.debug('CAhandler._config_server_load() ended')

    def _config_auth_load(self, config_dic):
        """ load authentication information """
        self.logger.debug('CAhandler._config_auth_load()')

        if 'CAhandler' in config_dic and 'username' in config_dic['CAhandler']:
            self.username = config_dic['CAhandler']['username']

        if 'CAhandler' in config_dic and 'enrollment_code' in config_dic['CAhandler']:
            self.enrollment_code = config_dic['CAhandler']['enrollment_code']

        if 'CAhandler' in config_dic and 'cert_file' in config_dic['CAhandler'] and 'cert_passphrase' in config_dic['CAhandler']:
            with requests.Session() as self.session:
                self.session.mount(self.api_host, Pkcs12Adapter(pkcs12_filename=config_dic['CAhandler']['cert_file'], pkcs12_password=config_dic['CAhandler']['cert_passphrase']))
        else:
            self.logger.error('CAhandler._config_load(): configuration incomplete: "cert_file"/"cert_passphrase" parameter is missing in configuration file.')

        self.logger.debug('CAhandler._config_auth_load() ended')

    def _config_cainfo_load(self, config_dic):
        """ load ca information """
        self.logger.debug('CAhandler._config_cainfo_load()')

        if 'CAhandler' in config_dic and 'ca_name' in config_dic['CAhandler']:
            self.ca_name = config_dic['CAhandler']['ca_name']

        if 'CAhandler' in config_dic and 'cert_profile_name' in config_dic['CAhandler']:
            self.cert_profile_name = config_dic['CAhandler']['cert_profile_name']

        if 'CAhandler' in config_dic and 'ee_profile_name' in config_dic['CAhandler']:
            self.ee_profile_name = config_dic['CAhandler']['ee_profile_name']

        self.logger.debug('CAhandler._config_cainfo_load() ended')

    def _config_load(self):
        """" load config from file """
        self.logger.debug('CAhandler._config_load()')

        config_dic = load_config(self.logger, 'CAhandler')

        # load configuration
        self._config_server_load(config_dic)
        self._config_auth_load(config_dic)
        self._config_cainfo_load(config_dic)

        # check configuration for completeness
        variable_dic = self.__dict__
        for ele in ['api_host', 'cert_profile_name', 'ee_profile_name', 'ca_name', 'username', 'enrollment_code']:
            if not variable_dic[ele]:
                self.logger.error('CAhandler._config_load(): configuration incomplete: parameter "{0}" is missing in configuration file.'.format(ele))
        self.logger.debug('CAhandler._config_load() ended')

    def _api_post(self, url, data):
        """ generic wrapper for an API post call """
        self.logger.debug('_api_post({0})'.format(url))

        try:
            api_response = self.session.post(url, json=data, proxies=self.proxy, verify=self.ca_bundle, timeout=self.request_timeout).json()
        except Exception as err_:
            self.logger.error('CAhandler._api_post() returned error: {0}'.format(err_))
            api_response = str(err_)

        return api_response

    def _api_put(self, url):
        """ generic wrapper for an API put call """
        self.logger.debug('_api_put({0})'.format(url))

        try:
            api_response = self.session.put(url, proxies=self.proxy, verify=self.ca_bundle, timeout=self.request_timeout).json()
        except Exception as err_:
            self.logger.error('CAhandler._api_put() returned error: {0}'.format(err_))
            api_response = str(err_)

        return api_response

    def _status_get(self):
        """ get status of the rest-api """
        self.logger.debug('_status_get()')

        if self.api_host:
            try:
                api_response = self.session.get(self.api_host + '/ejbca/ejbca-rest-api/v1/certificate/status', proxies=self.proxy, verify=self.ca_bundle, timeout=self.request_timeout).json()
            except Exception as err_:
                self.logger.error('CAhandler._ca_get() returned error: {0}'.format(str(err_)))
                api_response = {'status': 'nok', 'error': str(err_)}
        else:
            self.logger.error('CAhandler._status_get(): api_host is misisng in configuration')
            api_response = {}

        self.logger.debug('CAhandler._status_get() ended')
        return api_response

    def _sign(self, csr):
        """ submit CSR for signing """
        self.logger.debug('CAhandler._sign()')
        data_dic = {
            "certificate_request": csr,
            "certificate_profile_name": self.cert_profile_name,
            "end_entity_profile_name": self.ee_profile_name,
            "certificate_authority_name": self.ca_name,
            "username": self.username,
            "password": self.enrollment_code,
            "include_chain": True,
        }

        if self.api_host:
            sign_response = self._api_post(self.api_host + "/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll", data_dic)
        else:
            self.logger.error('CAhandler._status_get(): api_host is misisng in configuration')
            sign_response = {}

        return sign_response

    def enroll(self, csr):
        """ enroll certificate  """
        self.logger.debug('CAhandler.enroll()')

        cert_bundle = None
        error = None
        cert_raw = None
        poll_indentifier = None

        status_dic = self._status_get()

        if 'status' in status_dic and status_dic['status'].lower() == 'ok':

            # prepare the CSR to be signed
            csr = build_pem_file(self.logger, None, b64_url_recode(self.logger, csr), None, True)
            sign_response = self._sign(csr)

            if 'certificate' in sign_response and 'certificate_chain' in sign_response:
                cert_raw = sign_response['certificate']
                cert_bundle = convert_byte_to_string(cert_der2pem(b64_decode(self.logger, cert_raw)))
                for ca_cert in sign_response['certificate_chain']:
                    cert_bundle = '{0}{1}'.format(cert_bundle, convert_byte_to_string(cert_der2pem(b64_decode(self.logger, ca_cert))))
            else:
                error = 'Malformed response'
                self.logger.error('CAhandler.enroll(): Malformed Rest response')

        else:
            if 'error' in status_dic:
                error = status_dic['error']
            else:
                error = 'Unknown error'
                self.logger.error('CAhandler.enroll(): Unknown error')

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
        issuer_dn = cert_issuer_get(self.logger, cert)

        # check status
        certstatus_dic = self._cert_status_check(issuer_dn, cert_serial)

        if 'revoked' in certstatus_dic:
            if not certstatus_dic['revoked']:
                # this is the revocation path
                path = "/ejbca/ejbca-rest-api/v1/certificate/{0}/{1}/revoke?reason={2}".format(encode_url(self.logger, issuer_dn), cert_serial, rev_reason.upper())
                revoke_response = self._api_put(self.api_host + path)

                if 'revoked' in revoke_response and revoke_response['revoked']:
                    code = 200
                else:
                    code = 400
                    message = 'urn:ietf:params:acme:error:serverInternal'
                    detail = str(revoke_response)
            else:
                # already revoked
                code = 400
                message = 'urn:ietf:params:acme:error:alreadyRevoked'
                detail = 'Certificate has already been revoked'
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
