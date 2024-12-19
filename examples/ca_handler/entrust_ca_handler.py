# -*- coding: utf-8 -*-
""" CA handler using Entrust ECS Enterprise"""
from __future__ import print_function
from typing import Tuple, Dict, List
import datetime
import os
import requests
from requests_pkcs12 import Pkcs12Adapter
# pylint: disable=e0401
from acme_srv.helper import load_config, cert_pem2der, b64_encode, eab_profile_header_info_check, uts_now, uts_to_date_utc, cert_serial_get, config_eab_profile_load, config_headerinfo_load, header_info_get, b64_url_recode, request_operation, csr_cn_lookup, config_enroll_config_log_load, enrollment_config_log, config_allowed_domainlist_load, allowed_domainlist_check_error


CONTENT_TYPE = 'application/json'


# hardcoded Entrust Root Certification Authority - G2
ENTRUST_ROOT_CA = '''-----BEGIN CERTIFICATE-----
MIIEPjCCAyagAwIBAgIESlOMKDANBgkqhkiG9w0BAQsFADCBvjELMAkGA1UEBhMC
VVMxFjAUBgNVBAoTDUVudHJ1c3QsIEluYy4xKDAmBgNVBAsTH1NlZSB3d3cuZW50
cnVzdC5uZXQvbGVnYWwtdGVybXMxOTA3BgNVBAsTMChjKSAyMDA5IEVudHJ1c3Qs
IEluYy4gLSBmb3IgYXV0aG9yaXplZCB1c2Ugb25seTEyMDAGA1UEAxMpRW50cnVz
dCBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IC0gRzIwHhcNMDkwNzA3MTcy
NTU0WhcNMzAxMjA3MTc1NTU0WjCBvjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUVu
dHJ1c3QsIEluYy4xKDAmBgNVBAsTH1NlZSB3d3cuZW50cnVzdC5uZXQvbGVnYWwt
dGVybXMxOTA3BgNVBAsTMChjKSAyMDA5IEVudHJ1c3QsIEluYy4gLSBmb3IgYXV0
aG9yaXplZCB1c2Ugb25seTEyMDAGA1UEAxMpRW50cnVzdCBSb290IENlcnRpZmlj
YXRpb24gQXV0aG9yaXR5IC0gRzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC6hLZy254Ma+KZ6TABp3bqMriVQRrJ2mFOWHLP/vaCeb9zYQYKpSfYs1/T
RU4cctZOMvJyig/3gxnQaoCAAEUesMfnmr8SVycco2gvCoe9amsOXmXzHHfV1IWN
cCG0szLni6LVhjkCsbjSR87kyUnEO6fe+1R9V77w6G7CebI6C1XiUJgWMhNcL3hW
wcKUs/Ja5CeanyTXxuzQmyWC48zCxEXFjJd6BmsqEZ+pCm5IO2/b1BEZQvePB7/1
U1+cPvQXLOZprE4yTGJ36rfo5bs0vBmLrpxR57d+tVOxMyLlbc9wPBr64ptntoP0
jaWvYkxN4FisZDQSA/i2jZRjJKRxAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAP
BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRqciZ60B7vfec7aVHUbI2fkBJmqzAN
BgkqhkiG9w0BAQsFAAOCAQEAeZ8dlsa2eT8ijYfThwMEYGprmi5ZiXMRrEPR9RP/
jTkrwPK9T3CMqS/qF8QLVJ7UG5aYMzyorWKiAHarWWluBh1+xLlEjZivEtRh2woZ
Rkfz6/djwUAFQKXSt/S1mja/qYh2iARVBCuch38aNzx+LaUa2NSJXsq9rD1s2G2v
1fN2D807iDginWyTmsQ9v4IbZT+mD12q/OWyFcq1rca8PdCE6OoGcrBNOTJ4vz4R
nAuknZoh8/CbCzB428Hch0P+vGOaysXCHMnHjf87ElgI5rY97HosTvuDls4MPGmH
VHOkc8KT/1EQrBVUAdj8BbGJoX90g5pJ19xOe4pIb4tF9g==
-----END CERTIFICATE-----
'''


class CAhandler(object):
    """ Digicert CertCentralAP handler """

    def __init__(self, _debug: bool = None, logger: object = None):
        self.logger = logger
        self.api_url = 'https://api.entrust.net/enterprise/v2'
        self.client_cert = None
        self.cert_passphrase = None
        self.username = None
        self.password = None
        self.organization_name = None
        self.certtype = 'STANDARD_SSL'
        self.cert_validity_days = 365
        self.entrust_root_cert = ENTRUST_ROOT_CA
        self.proxy = None
        self.session = None
        self.request_timeout = 10

        self.allowed_domainlist = []
        self.header_info_field = False
        self.eab_handler = None
        self.eab_profiling = False
        self.enrollment_config_log = False
        self.enrollment_config_log_skip_list = []

    def __enter__(self):
        """ Makes CAhandler a Context Manager """
        if not self.session:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _api_get(self, url: str) -> Tuple[int, Dict[str, str]]:
        """ post data to API """
        self.logger.debug('CAhandler._api_get()')
        headers = {
            'Content-Type': CONTENT_TYPE
        }

        code, content = request_operation(self.logger, session=self.session, method='get', url=url, headers=headers, proxy=self.proxy, timeout=self.request_timeout, payload=None)
        self.logger.debug('CAhandler._api_get() ended with code: %s', code)
        return code, content

    def _api_post(self, url: str, data: Dict[str, str]) -> Tuple[int, Dict[str, str]]:
        """ post data to API """
        self.logger.debug('CAhandler._api_post()')
        headers = {
            'Content-Type': CONTENT_TYPE
        }
        code, content = request_operation(self.logger, session=self.session, method='post', url=url, headers=headers, proxy=self.proxy, timeout=self.request_timeout, payload=data)
        self.logger.debug('CAhandler._api_post() ended with code: %s', code)
        return code, content

    def _api_put(self, url: str, data: Dict[str, str]) -> Tuple[int, Dict[str, str]]:
        """ post data to API """
        self.logger.debug('CAhandler._api_put()')
        headers = {
            'Content-Type': CONTENT_TYPE
        }
        code, content = request_operation(self.logger, session=self.session, method='put', url=url, headers=headers, proxy=self.proxy, timeout=self.request_timeout, payload=data)

        self.logger.debug('CAhandler._api_put() ended with code: %s', code)
        return code, content

    def _certificates_get_from_serial(self, cert_serial: str) -> List[str]:
        """ get certificates """
        self.logger.debug('CAhandler._certificates_get_from_serial()')

        # for some reason entrust custs leading zeros from serial number
        if cert_serial.startswith('0'):
            self.logger.info('CAhandler._certificates_get_from_serial() remove leading zeros from serial number')
            cert_serial = cert_serial.lstrip('0')

        code, content = self._api_get(self.api_url + f'/certificates?serialNumber={cert_serial}')

        if code == 200 and 'certificates' in content:
            cert_list = content['certificates']
        else:
            self.logger.error('CAhandler._certificates_get_from_serial() for %s failed with code: %s', cert_serial, code)
            cert_list = []

        self.logger.debug('CAhandler._certificates_get_from_serial() ended with code: %s and %s certificate', code, len(cert_list))
        return cert_list

    def _config_load(self):
        """" load config from file """
        self.logger.debug('CAhandler._config_load()')

        config_dic = load_config(self.logger, 'CAhandler')
        if 'CAhandler' in config_dic:
            cfg_dic = dict(config_dic['CAhandler'])
            self.api_url = cfg_dic.get('api_url', 'https://api.entrust.net/enterprise/v2')
            try:
                self.request_timeout = int(cfg_dic.get('request_timeout', 10))
            except Exception as err:
                self.logger.error('CAhandler._config_load(): failed to parse request_timeout %s', err)
            try:
                self.cert_validity_days = int(cfg_dic.get('cert_validity_days', 365))
            except Exception as err:
                self.logger.error('CAhandler._config_load(): failed to parse cert_validity_days %s', err)

            self.username = cfg_dic.get('username', None)
            self.password = cfg_dic.get('password', None)
            self.organization_name = cfg_dic.get('organization_name', None)
            self.certtype = cfg_dic.get('certtype', 'STANDARD_SSL')
            self._config_session_load(config_dic)

            # load root CA
            self._config_root_load(config_dic)

        # load allowed domainlist
        self.allowed_domainlist = config_allowed_domainlist_load(self.logger, config_dic)
        # load profiling
        self.eab_profiling, self.eab_handler = config_eab_profile_load(self.logger, config_dic)
        # load header info
        self.header_info_field = config_headerinfo_load(self.logger, config_dic)
        # load enrollment config log
        self.enrollment_config_log, self.enrollment_config_log_skip_list = config_enroll_config_log_load(self.logger, config_dic)

        self.logger.debug('CAhandler._config_load() ended')

    def _config_passphrase_load(self, config_dic: Dict[str, str]):
        """ load passphrase """
        self.logger.debug('CAhandler._config_passphrase_load()')
        if 'cert_passphrase_variable' in config_dic['CAhandler'] or 'cert_passphrase' in config_dic['CAhandler']:
            if 'cert_passphrase_variable' in config_dic['CAhandler']:
                self.logger.debug('CAhandler._config_passphrase_load(): load passphrase from environment variable')
                try:
                    self.cert_passphrase = os.environ[config_dic['CAhandler']['cert_passphrase_variable']]
                except Exception as err:
                    self.logger.error('CAhandler._config_passphrase_load() could not load cert_passphrase_variable:%s', err)

            if 'cert_passphrase' in config_dic['CAhandler']:
                self.logger.debug('CAhandler._config_passphrase_load(): load passphrase from config file')
                if self.cert_passphrase:
                    self.logger.info('CAhandler._config_load() overwrite cert_passphrase')
                self.cert_passphrase = config_dic['CAhandler']['cert_passphrase']
        self.logger.debug('CAhandler._config_passphrase_load() ended')

    def _config_root_load(self, config_dic: Dict[str, str]):
        """ load root CA """
        self.logger.debug('CAhandler._config_root_load()')
        if 'entrust_root_cert' in config_dic['CAhandler']:
            if os.path.isfile(config_dic['CAhandler']['entrust_root_cert']):
                self.logger.debug('CAhandler._config_root_load(): load root CA from config file')
                with open(config_dic['CAhandler']['entrust_root_cert'], 'r', encoding='utf8') as ca_file:
                    self.entrust_root_cert = ca_file.read()
            else:
                self.logger.error('CAhandler._config_root_load(): root CA file configured but not not found. Using default one.')

        self.logger.debug('CAhandler._config_root_load() ended')

    def _config_session_load(self, config_dic: Dict[str, str]):
        """ load session """
        self.logger.debug('CAhandler._config_session_load()')

        with requests.Session() as self.session:
            # client auth via pem files
            if 'client_cert' in config_dic['CAhandler'] and 'client_key' in config_dic['CAhandler']:
                self.logger.debug('CAhandler._config_session_load() cert and key in pem format')
                self.session.cert = (config_dic['CAhandler']['client_cert'], config_dic['CAhandler']['client_key'])

            else:
                self._config_passphrase_load(config_dic)
                if 'client_cert' in config_dic['CAhandler'] and self.cert_passphrase:
                    self.logger.debug('CAhandler._config_session_load() cert and passphrase')
                    self.session.mount(self.api_url, Pkcs12Adapter(pkcs12_filename=config_dic['CAhandler']['client_cert'], pkcs12_password=self.cert_passphrase))
                else:
                    self.logger.warning('CAhandler._config_load() configuration might be incomplete: "client_cert. "client_key" or "client_passphrase[_variable] parameter is missing in config file')
            self.session.auth = (self.username, self.password)

        self.logger.debug('CAhandler._config_session_load() ended')

    def _org_domain_cfg_check(self) -> str:
        """ check organizations """
        self.logger.debug('CAhandler._organizations_check()')

        error = None
        org_dic = self._organizations_get()
        if self.organization_name not in org_dic:
            error = f'Organization {self.organization_name} not found in Entrust API'
            self.logger.error('CAhandler._organizations_check() ended with error: %s', error)
        else:
            domain_list = self._domains_get(org_dic[self.organization_name])
            if not self.allowed_domainlist:
                self.logger.info('CAhandler._organizations_check(): allowed_domainlist is empty, using domains from Entrust API')
                self.allowed_domainlist = domain_list

        self.logger.debug('CAhandler._organizations_check() ended with %s', error)
        return error

    def _organizations_get(self) -> Dict[str, str]:
        """ get organizations """
        self.logger.debug('CAhandler._organizations_get()')

        code, content = self._api_get(self.api_url + '/organizations')
        org_dic = {}
        if code == 200 and 'organizations' in content:
            self.logger.debug('CAhandler._organizations_get() ended with code: 200')
            for org in content['organizations']:
                if 'verificationStatus' in org and org['verificationStatus'] == 'APPROVED':
                    if 'name' in org and 'clientId' in org:
                        org_dic[org['name']] = org['clientId']
        else:
            self.logger.error('CAhandler._organizations_get(): malformed response')

        self.logger.debug('CAhandler._organizations_get() ended with code: %s', code)
        return org_dic

    def _domains_get(self, org_id: str) -> List[str]:
        """ get domains """
        self.logger.debug('CAhandler._domains_get()')

        code, content = self._api_get(self.api_url + f'/clients/{org_id}/domains')

        api_domain_list = []
        if code == 200 and 'domains' in content:
            self.logger.debug('CAhandler._domains_get() ended with code: 200')

            for domain in content['domains']:
                if 'verificationStatus' in domain and domain['verificationStatus'] == 'APPROVED':
                    if 'domainName' in domain:
                        api_domain_list.append(domain['domainName'])
        else:
            self.logger.error('CAhandler._domains_get(): malformed response')

        self.logger.debug('CAhandler._domains_get() ended with code: %s', code)
        return api_domain_list

    def credential_check(self):
        """ test connection to Entrust api """
        self.logger.debug('CAhandler.credential_check()')

        error = None
        code, content = self._api_get(self.api_url + '/application/version')
        if code != 200:
            error = f'Connection to Entrust API failed: {content}'

        self.logger.debug('CAhandler.credential_check() ended with code: %s', code)
        return error

    def _config_check(self) -> str:
        """ check config """
        self.logger.debug('CAhandler._config_check()')

        error = None
        for ele in ['api_url', 'username', 'password', 'organization_name']:
            if not getattr(self, ele):
                error = f'{ele} parameter in missing in config file'
                self.logger.error('CAhandler._config_check() ended with error: %s', error)
                break

        self.logger.debug('CAhandler._config_check() ended with: %s', error)
        return error

    def _enroll_check(self, csr: str) -> str:
        """ check csr """
        self.logger.debug('CAhandler._enroll_check()')

        # check for eab profiling and header_info
        error = eab_profile_header_info_check(self.logger, self, csr, 'cert_type')

        if not error:
            error = self._config_check()

        if not error:
            error = self._org_domain_cfg_check()

        if not error:
            # check for allowed domainlist
            error = allowed_domainlist_check_error(self.logger, csr, self.allowed_domainlist)

        if not error:
            error = self.credential_check()

        self.logger.debug('CAhandler._enroll_check() ended with %s', error)
        return error

    def _trackingid_get(self, cert_raw: str) -> int:
        """ get tracking id """
        self.logger.debug('CAhandler._trackingid_get()')

        tracking_id = None
        # we misuse header_info_get() to get the tracking id from database
        cert_recode = b64_url_recode(self.logger, cert_raw)
        pid_list = header_info_get(self.logger, csr=cert_recode, vlist=['poll_identifier'], field_name='cert_raw')

        for ele in pid_list:
            if 'poll_identifier' in ele:
                tracking_id = ele['poll_identifier']
                break

        if not tracking_id:
            # lookup through Entrust API
            self.logger.info('CAhandler._trackingid_get(): tracking_id not found in database. Lookup trough Entrust API')
            cert_serial = cert_serial_get(self.logger, cert_raw, hexformat=True)
            certificate_list = self._certificates_get_from_serial(cert_serial)
            for ele in certificate_list:
                if 'trackingId' in ele:
                    tracking_id = ele['trackingId']
                    break

        self.logger.debug('CAhandler._trackingid_get() ended with %s', tracking_id)
        return tracking_id

    def _response_parse(self, content: Dict[str, str]) -> Tuple[str, str]:
        """ parse response """
        self.logger.debug('CAhandler._response_parse()')

        cert_bundle = None
        cert_raw = None
        poll_indentifier = None

        if 'trackingId' in content:
            poll_indentifier = content['trackingId']
        if 'endEntityCert' in content and 'chainCerts' in content:
            cert_raw = b64_encode(self.logger, cert_pem2der(content['endEntityCert']))
            for cnt, ca_cert in enumerate(content['chainCerts']):
                if cnt == 0:
                    cert_bundle = ca_cert + '\n'
                else:
                    cert_bundle += ca_cert + '\n'

            # add Entrust Root CA
            if cert_bundle:
                cert_bundle += self.entrust_root_cert + '\n'
            else:
                cert_bundle = self.entrust_root_cert + '\n'
        self.logger.debug('CAhandler._response_parse() ended')
        return cert_bundle, cert_raw, poll_indentifier

    def _enroll(self, csr: str) -> Tuple[str, str]:
        """ enroll certificate """
        self.logger.debug('CAhandler._enroll()')

        error = None
        cert_raw = None
        cert_bundle = None
        poll_indentifier = None

        if self.enrollment_config_log:
            self.enrollment_config_log_skip_list.extend(['cert_passphrase', 'client_key'])
            enrollment_config_log(self.logger, self, self.enrollment_config_log_skip_list)

        # get CN and SANs
        cn = csr_cn_lookup(self.logger, csr)

        # calculate cert expiry date
        certexpirydate = datetime.datetime.now() + datetime.timedelta(days=self.cert_validity_days)

        data_dic = {
            'csr': csr,
            'signingAlg': 'SHA-2',
            'eku': "SERVER_AND_CLIENT_AUTH",
            'cn': cn,
            'org': self.organization_name,
            'endUserKeyStorageAgreement': True,
            'certType': self.certtype,
            "certExpiryDate": certexpirydate.strftime('%Y-%m-%d')
        }

        code, content = self._api_post(self.api_url + '/certificates', data_dic)

        if code == 201:
            cert_bundle, cert_raw, poll_indentifier = self._response_parse(content)
        else:
            if 'errors' in content:
                error = f"Error during order creation: {code} - {content['errors']}"
            else:
                error = f'Error during order creation: {code} - {content}'
            self.logger.error('CAhandler._enroll() failed with error: %s', error)

        self.logger.debug('CAhandler._enroll() ended with code: %s', code)
        return error, cert_bundle, cert_raw, poll_indentifier

    def revoke_by_trackingid(self, tracking_id: int, _rev_reason: str = 'unspecified') -> Tuple[int, str]:
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke_by_trackingid()')
        code, content = self._api_post(self.api_url + f'/certificates/{tracking_id}/revocations', {'crlReason': _rev_reason, 'revocationComment': 'revoked by acme2certifier'})
        self.logger.debug('CAhandler.revoke_by_trackingid() ended with code: %s', code)
        return code, content

    def _total_get(self, content: str) -> int:
        """ get total number of certificates """
        self.logger.debug('CAhandler._total_get()')
        total = 1

        if isinstance(content, dict) and 'summary' in content and 'total' in content['summary']:
            self.logger.debug('CAhandler.certificates_get() total number of certificates: %s', content['summary']['total'])
            total = content['summary']['total']   # get total number of certificates
        else:
            self.logger.error('CAhandler.certificates_get() failed did not get any total value: %s', content)
            raise StopIteration('Certificates lookup failed: did not get any total value')

        self.logger.debug('CAhandler._total_get() ended with %s', total)
        return total

    def certificates_get(self, limit=200) -> List[str]:
        """ get certificates """
        self.logger.debug('CAhandler.certificates_get()')

        # set initial values
        offset = 0
        cert_list = []
        prev_data = []
        total = 1
        while len(cert_list) < total:
            self.logger.info('fetching certs offset: %s, limit: %s, total: %s, buffered: %s', offset, limit, total, len(cert_list))
            code, content = self._api_get(self.api_url + f'/certificates?limit={limit}&offset={offset}')
            if code == 200:
                if offset == 0:
                    # updte totals or throw error
                    total = self._total_get(content)

                # extend certificate list or throw error
                if 'certificates' in content:
                    # cover cases where we wont get new data as we have to avoid loops
                    if prev_data != content['certificates']:
                        cert_list.extend(content['certificates'])
                        prev_data = content['certificates']
                        offset = offset + limit
                    else:
                        self.logger.error('CAhandler.certificates_get() failed to get new data')
                        break
            else:
                self.logger.error('CAhandler.certificates_get() failed with code: %s', code)
                break

        self.logger.debug('CAhandler.certificates_get() ended with code: %s and %s certificate', code, len(cert_list))
        return cert_list

    def enroll(self, csr: str) -> Tuple[str, str, str, str]:
        """ enroll certificate  """
        self.logger.debug('CAhandler.enroll()')

        cert_bundle = None
        error = None
        cert_raw = None
        poll_indentifier = None

        error = self._enroll_check(csr)

        if not error:
            error, cert_bundle, cert_raw, poll_indentifier = self._enroll(csr)

        self.logger.debug('Certificate.enroll() ended')
        return error, cert_bundle, cert_raw, poll_indentifier

    def poll(self, _cert_name: str, poll_identifier: str, _csr: str) -> Tuple[str, str, str, str, bool]:
        """ poll status of pending CSR and download certificates """
        self.logger.debug('CAhandler.poll()')

        error = 'Method not implemented.'
        cert_bundle = None
        cert_raw = None
        rejected = False

        self.logger.debug('CAhandler.poll() ended')
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(self, certificate_raw: str, _rev_reason: str = 'unspecified', _rev_date: str = uts_to_date_utc(uts_now())) -> Tuple[int, str, str]:
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke()')

        code = None
        message = None
        detail = None

        # get tracking id as input for revocation call
        tracking_id = self._trackingid_get(certificate_raw)

        if tracking_id:
            code, content = self.revoke_by_trackingid(tracking_id, _rev_reason)
            if code == 200:
                message = 'Certificate revoked'
            else:
                code = 500
                message = 'urn:ietf:params:acme:error:serverInternal'
                detail = content
        else:
            code = 500
            message = 'urn:ietf:params:acme:error:serverInternal'
            detail = 'Failed to get tracking id'

        self.logger.debug('CAhandler.poll() ended')

        self.logger.debug('Certificate.revoke() ended')
        return (code, message, detail)

    def trigger(self, _payload: str) -> Tuple[str, str, str]:
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')

        error = 'Method not implemented.'
        cert_bundle = None
        cert_raw = None

        self.logger.debug('CAhandler.trigger() ended with error: %s', error)
        return (error, cert_bundle, cert_raw)
