# -*- coding: utf-8 -*-
# pylint: disable=r0902, r0912, r0913, r0915
""" certificate class """
from __future__ import print_function
import json
from typing import List, Tuple, Dict
from acme_srv.helper import b64_url_recode, generate_random_string, cert_cn_get, cert_san_get, cert_extensions_get, hooks_load, uts_now, uts_to_date_utc, date_to_uts_utc, load_config, csr_san_get, csr_extensions_get, cert_dates_get, ca_handler_load, error_dic_get, string_sanitize, pembundle_to_list, certid_asn1_get, cert_serial_get, cert_aki_get
from acme_srv.db_handler import DBstore
from acme_srv.message import Message
from acme_srv.threadwithreturnvalue import ThreadWithReturnValue


class Certificate(object):
    """ CA  handler """

    def __init__(self, debug: bool = False, srv_name: str = None, logger=None):
        self.debug = debug
        self.server_name = srv_name
        self.logger = logger
        self.cahandler = None
        self.dbstore = DBstore(self.debug, self.logger)
        self.err_msg_dic = error_dic_get(self.logger)
        self.hooks = None
        self.ignore_pre_hook_failure = False
        self.ignore_post_hook_failure = True
        self.ignore_success_hook_failure = False
        self.message = Message(self.debug, self.server_name, self.logger)
        self.path_dic = {'cert_path': '/acme/cert/'}
        self.retry_after = 600
        self.tnauthlist_support = False
        self.cert_reusage_timeframe = 0
        self.enrollment_timeout = 5
        self.cn2san_add = False

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _account_check(self, account_name: str, certificate: str) -> Dict[str, str]:
        """ check account """
        self.logger.debug('Certificate.issuer_check()')
        try:
            result = self.dbstore.certificate_account_check(account_name, b64_url_recode(self.logger, certificate))
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Certificate._account_check(): %s', err_)
            result = None
        return result

    def _authz_check(self, identifier_dic: Dict[str, str], certificate: str) -> List[str]:
        self.logger.debug('Certificate._authz_check()')
        # load identifiers
        try:
            identifiers = json.loads(identifier_dic['identifiers'].lower())
        except Exception:
            identifiers = []

        # check if we have a tnauthlist identifier
        tnauthlist_identifer_in = self._tnauth_identifier_check(identifiers)
        if self.tnauthlist_support and tnauthlist_identifer_in:
            try:
                # get list of certextensions in base64 format and identifier status
                tnauthlist = cert_extensions_get(self.logger, certificate)
                identifier_status = self._identifer_tnauth_list(identifier_dic, tnauthlist)
            except Exception as err_:
                # enough to set identifier_list as empty list
                identifier_status = []
                self.logger.warning('Certificate._authorization_check() error while loading parsing certifcate. Error: %s', err_)
        else:
            try:
                # get sans
                san_list = cert_san_get(self.logger, certificate)
                if self.cn2san_add:
                    # add common name to SANs
                    cert_cn = cert_cn_get(self.logger, certificate)
                    if not san_list and cert_cn:
                        san_list.append(f'DNS:{cert_cn}')

                identifier_status = self._identifer_status_list(identifiers, san_list)
            except Exception as err_:
                # enough to set identifier_list as empty list
                identifier_status = []
                self.logger.warning('Certificate._authorization_check() error while loading parsing certifcate. Error: %s', err_)

        self.logger.debug('Certificate._authz_check() ended')
        return identifier_status

    def _authorization_check(self, order_name: str, certificate: str) -> bool:
        """ check if an acount holds authorization for all identifiers = SANs in the certificate """
        self.logger.debug('Certificate._authorization_check()')

        # empty list of statuses
        identifier_status = []

        # get identifiers for order
        try:
            identifier_dic = self.dbstore.order_lookup('name', order_name, ['identifiers'])
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Certificate._authorization_check(): %s', err_)
            identifier_dic = {}

        if identifier_dic and 'identifiers' in identifier_dic:
            # get identifier status list
            identifier_status = self._authz_check(identifier_dic, certificate)

        result = False
        if identifier_status and False not in identifier_status:
            result = True

        self.logger.debug('Certificate._authorization_check() ended with %s', result)
        return result

    def _cert_reusage_check(self, csr: str) -> Tuple[None, str, str, str]:
        """ check if an existing certificate an be reused """
        self.logger.debug('Certificate._cert_reusage_check(%s)', self.cert_reusage_timeframe)

        try:
            result_dic = self.dbstore.certificates_search('csr', csr, ('cert', 'cert_raw', 'expire_uts', 'issue_uts', 'created_at', 'id'))
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Certificate._cert_reusage_check(): %s', err_)
            result_dic = None

        cert = None
        cert_raw = None
        message = None

        if result_dic:
            uts = uts_now()
            # sort certificates by creation date
            for certificate in sorted(result_dic, key=lambda i: i['issue_uts'], reverse=True):
                try:
                    uts_create = date_to_uts_utc(certificate['created_at'])
                except Exception as _err:
                    self.logger.error('acme2certifier date_to_uts_utc() error in Certificate._cert_reusage_check(): id:%s/created_at:%s', certificate['id'], certificate['created_at'])
                    uts_create = 0

                # check if there certificates within reusage timeframe
                if certificate['cert_raw'] and certificate['cert'] and uts - self.cert_reusage_timeframe <= uts_create:
                    # exclude expired certificates
                    if uts <= certificate['expire_uts']:
                        cert = certificate['cert']
                        cert_raw = certificate['cert_raw']
                        message = f'reused certificate from id: {certificate["id"]}'
                        break

        self.logger.debug('Certificate._cert_reusage_check() ended with {%s', message)
        return (None, cert, cert_raw, message)

    def _config_hooks_load(self, config_dic: Dict[str, str]):
        """ load hook configuration """
        self.logger.debug('Certificate._config_hooks_load()')

        # load hooks according to configuration
        hooks_module = hooks_load(self.logger, config_dic)
        if hooks_module:
            try:
                # store handler in variable
                self.hooks = hooks_module.Hooks(self.logger)
            except Exception as err:
                self.logger.critical('Certificate._config_load(): Hooks could not be loaded: %s', err)

            self.ignore_pre_hook_failure = config_dic.getboolean('Hooks', 'ignore_pre_hook_failure', fallback=False)
            self.ignore_post_hook_failure = config_dic.getboolean('Hooks', 'ignore_post_hook_failure', fallback=True)
            self.ignore_success_hook_failure = config_dic.getboolean('Hooks', 'ignore_success_hook_failure', fallback=False)

        self.logger.debug('Certificate._config_hooks_load() ended')

    def _config_parameters_load(self, config_dic: Dict[str, str]):
        """ load various parameters """
        self.logger.debug('Certificate._config_parameters_load()')

        if 'Certificate' in config_dic:
            if 'cert_reusage_timeframe' in config_dic['Certificate']:
                try:
                    self.cert_reusage_timeframe = int(config_dic['Certificate']['cert_reusage_timeframe'])
                except Exception as err_:
                    self.logger.error('acme2certifier Certificate._config_load() cert_reusage_timout parsing error: %s', err_)
            if 'enrollment_timeout' in config_dic['Certificate']:
                try:
                    self.enrollment_timeout = int(config_dic['Certificate']['enrollment_timeout'])
                except Exception as err_:
                    self.logger.error('acme2certifier Certificate._config_load() enrollment_timeout parsing error: %s', err_)

        if 'Directory' in config_dic and 'url_prefix' in config_dic['Directory']:
            self.path_dic = {k: config_dic['Directory']['url_prefix'] + v for k, v in self.path_dic.items()}

        self.logger.debug('Certificate._config_parameters_load() ended')

    def _config_load(self):
        """" load config from file """
        self.logger.debug('Certificate._config_load()')
        config_dic = load_config()
        if 'Order' in config_dic:
            self.tnauthlist_support = config_dic.getboolean('Order', 'tnauthlist_support', fallback=False)

        if 'CAhandler' in config_dic and config_dic.get('CAhandler', 'handler_file', fallback=None) == 'examples/ca_handler/asa_ca_handler.py':
            self.cn2san_add = True
            self.logger.debug('Certificate._config_load(): cn2san_add enabled')

        # load ca_handler according to configuration
        ca_handler_module = ca_handler_load(self.logger, config_dic)

        if ca_handler_module:
            # store handler in variable
            self.cahandler = ca_handler_module.CAhandler
        else:
            self.logger.critical('Certificate._config_load(): No ca_handler loaded')

        # load hooks
        self._config_hooks_load(config_dic)

        # load parametrs
        self._config_parameters_load(config_dic)

        self.logger.debug('ca_handler: %s', ca_handler_module)
        self.logger.debug('Certificate._config_load() ended.')

    def _identifiers_load(self, identifier_dic: Dict[str, str], csr: str) -> List[str]:
        self.logger.debug('Certificate._identifiers_load()')
        # load identifiers
        try:
            identifiers = json.loads(identifier_dic['identifiers'].lower())
        except Exception:
            identifiers = []

        # do we need to check for tnauth
        tnauthlist_identifer_in = self._tnauth_identifier_check(identifiers)

        if self.tnauthlist_support and tnauthlist_identifer_in:
            # get list of certextensions in base64 format
            try:
                tnauthlist = csr_extensions_get(self.logger, csr)
                identifier_status = self._identifer_tnauth_list(identifier_dic, tnauthlist)
            except Exception as err_:
                identifier_status = []
                self.logger.warning('Certificate._csr_check() error while parsing csr.\nerror: %s', err_)
        else:
            # get sans and compare identifiers against san
            try:
                san_list = csr_san_get(self.logger, csr)
                identifier_status = self._identifer_status_list(identifiers, san_list)
            except Exception as err_:
                identifier_status = []
                self.logger.warning('Certificate._csr_check() error while checking csr.\nerror: %s', err_)

        self.logger.debug('Certificate._identifiers_load() ended with %s', identifier_status)
        return identifier_status

    def _csr_check(self, certificate_name: str, csr: str) -> bool:
        """ compare csr extensions against order """
        self.logger.debug('Certificate._csr_check()')

        # fetch certificate dictionary from DB
        certificate_dic = self._info(certificate_name)
        self.logger.debug('Certificate._info() ended with:%s', certificate_dic)

        # empty list of statuses
        identifier_status = []

        if 'order' in certificate_dic:
            # get identifiers for order
            try:
                identifier_dic = self.dbstore.order_lookup('name', certificate_dic['order'], ['identifiers'])
            except Exception as err_:
                self.logger.critical('acme2certifier database error in Certificate._csr_check(): %s', err_)
                identifier_dic = {}

            if identifier_dic and 'identifiers' in identifier_dic:
                identifier_status = self._identifiers_load(identifier_dic, csr)

        csr_check_result = False

        if identifier_status and False not in identifier_status:
            csr_check_result = True

        self.logger.debug('Certificate._csr_check() ended with %s', csr_check_result)
        return csr_check_result

    def _enroll(self, csr: str, ca_handler: object) -> Tuple[str, str, str, str]:
        self.logger.debug('Certificate._enroll()')
        if self.cert_reusage_timeframe:
            (error, certificate, certificate_raw, poll_identifier) = self._cert_reusage_check(csr)
        else:
            certificate = None
            certificate_raw = None

        if not certificate or not certificate_raw:
            self.logger.debug('Certificate._enroll(): trigger enrollment')
            (error, certificate, certificate_raw, poll_identifier) = ca_handler.enroll(csr)
        else:
            self.logger.info('Certificate._enroll(): reuse existing certificate')

        self.logger.debug('Certificate._enroll() ended')
        return (error, certificate, certificate_raw, poll_identifier)

    def _renewal_info_get(self, certificate: str) -> str:
        """ get renewal info """
        self.logger.error('Certificate._renewal_info_get()')

        certificate_list = pembundle_to_list(self.logger, certificate)

        renewal_info_hex = certid_asn1_get(self.logger, certificate_list[0], certificate_list[1])

        self.logger.debug('Certificate.certid_asn1_get() ended with %s', renewal_info_hex)
        return renewal_info_hex

    def _store(self, certificate: str, certificate_raw: str, poll_identifier: str, certificate_name: str, order_name: str, csr: str) -> Tuple[int, str]:
        """ store  certificate """
        self.logger.error('Certificate._store()')

        error = None
        (issue_uts, expire_uts) = cert_dates_get(self.logger, certificate_raw)
        try:
            result = self._store_cert(certificate_name, certificate, certificate_raw, issue_uts, expire_uts, poll_identifier)
            if result:
                self._order_update({'name': order_name, 'status': 'valid'})
            if self.hooks:
                try:
                    self.hooks.success_hook(certificate_name, order_name, csr, certificate, certificate_raw, poll_identifier)
                    self.logger.debug('Certificate._enroll_and_store: success_hook successful')
                except Exception as err:
                    self.logger.error('Certificate._enroll_and_store: success_hook exception: %s', err)
                    if not self.ignore_success_hook_failure:
                        error = (None, 'success_hook_error', str(err))

        except Exception as err_:
            result = None
            self.logger.critical('acme2certifier database error in Certificate._enroll_and_store(): %s', err_)

        self.logger.error('Certificate._store() ended')
        return (result, error)

    def _enrollerror_handler(self, error: str, poll_identifier: str, order_name: str, certificate_name: str) -> Tuple[None, str, str]:
        """ store error message for later analysis """
        self.logger.debug('Certificate._enrollerror_handler(%s)', error)

        result = None
        detail = None
        try:
            if not poll_identifier:
                self.logger.debug('Certificate._enrollerror_handler(): invalidating order as there is no certificate and no poll_identifier: %s/%s', error, order_name)
                self._order_update({'name': order_name, 'status': 'invalid'})
            self._store_cert_error(certificate_name, error, poll_identifier)
        except Exception as err_:
            result = None
            self.logger.critical('acme2certifier database error in Certificate._enrollerror_handler() _store_cert_error: %s', err_)

        # cover polling cases
        if poll_identifier:
            detail = poll_identifier
        else:
            error = self.err_msg_dic['serverinternal']

        self.logger.debug('Certificate._enrollerror_handler() ended with: %s', result)
        return (result, error, detail)

    def _pre_hooks_process(self, certificate_name: str, order_name: str, csr: str) -> List[str]:
        self.logger.debug('Certificate._pre_hooks_process(%s, %s)', certificate_name, order_name)
        hook_error = []
        if self.hooks:
            try:
                self.hooks.pre_hook(certificate_name, order_name, csr)
                self.logger.debug('Certificate._pre_hooks_process(): pre_hook successful')
            except Exception as err:
                self.logger.error('Certificate._pre_hooks_process(): pre_hook exception: %s', err)
                if not self.ignore_pre_hook_failure:
                    hook_error = (None, 'pre_hook_error', str(err))

        self.logger.debug('Certificate._pre_hooks_process(%s)', hook_error)
        return hook_error

    def _post_hooks_process(self, certificate_name: str, order_name: str, csr: str, error: str) -> List[str]:
        self.logger.debug('Certificate._pre_hooks_process(%s, %s', certificate_name, order_name)

        hook_error = []
        if self.hooks:
            try:
                self.hooks.post_hook(certificate_name, order_name, csr, error)
                self.logger.debug('Certificate._pre_hooks_process(): post_hook successful')
            except Exception as err:
                self.logger.error('Certificate._pre_hooks_process(): post_hook exception: %s', err)
                if not self.ignore_post_hook_failure:
                    hook_error = (None, 'post_hook_error', str(err))

        self.logger.debug('Certificate._post_hooks_process(%s)', hook_error)
        return hook_error

    def _enroll_and_store(self, certificate_name: str, csr: str, order_name: str = None) -> Tuple[str, str, str]:
        """ enroll and store certificate """
        self.logger.debug('Certificate._enroll_and_store(%s, %s, %s)', certificate_name, order_name, csr)

        detail = None
        error = None

        hook_error = self._pre_hooks_process(certificate_name, order_name, csr)
        if hook_error:
            return hook_error

        with self.cahandler(self.debug, self.logger) as ca_handler:

            # enroll certificate
            (error, certificate, certificate_raw, poll_identifier) = self._enroll(csr, ca_handler)

            if certificate:
                (result, error) = self._store(certificate, certificate_raw, poll_identifier, certificate_name, order_name, csr)
                if error:
                    return error
            else:
                self.logger.error('acme2certifier enrollment error: %s', error)
                (result, error, detail) = self._enrollerror_handler(error, poll_identifier, order_name, certificate_name)

        hook_error = self._post_hooks_process(certificate_name, order_name, csr, error)
        if hook_error:
            return hook_error

        self.logger.debug('Certificate._enroll_and_store() ended with: %s:%s', result, error)
        return (result, error, detail)

    def _identifier_chk(self, cert_type: str, cert_value: str, identifiers: List[str], san_is_in: bool) -> bool:
        """ check identifier """
        self.logger.debug('Certificate._identifier_chk(%s/%s)', cert_type, cert_value)

        if cert_type and cert_value:
            for identifier in identifiers:
                if 'type' in identifier:
                    if (identifier['type'].lower() == cert_type and identifier['value'].lower() == cert_value):
                        san_is_in = True
                        break

        self.logger.debug('Certificate._identifier_chk(%s)', san_is_in)
        return san_is_in

    def _identifer_status_list(self, identifiers: List[str], san_list: List[str]) -> List[str]:
        """ compare identifiers and check if each san is in identifer list """
        self.logger.debug('Certificate._identifer_status_list()')

        identifier_status = []
        for san in san_list:
            san_is_in = False
            try:
                (cert_type, cert_value) = san.lower().split(':', 1)
            except Exception as err_:
                self.logger.error('Error while splitting san %s: %s', san, err_)
                cert_type = None
                cert_value = None

            # check identifiers
            san_is_in = self._identifier_chk(cert_type, cert_value, identifiers, san_is_in)

            self.logger.debug('SAN check for %s against identifiers returned %s', san.lower(), san_is_in)
            identifier_status.append(san_is_in)

        if not identifier_status:
            identifier_status.append(False)

        self.logger.debug('Certificate._identifer_status_list() ended with %s', identifier_status)
        return identifier_status

    def _identifier_tnauth_chk(self, identifier: Dict[str, str], tnauthlist: List[str]) -> bool:
        """ check tnauth identifier against tnauthlist """
        self.logger.debug('Certificate._identifier_tnauth_chk(%s)', identifier)

        result = False
        # get the tnauthlist identifier
        if 'type' in identifier and identifier['type'].lower() == 'tnauthlist':
            # check if tnauthlist extension is in extension list
            if 'value' in identifier and identifier['value'] in tnauthlist:
                result = True

        self.logger.debug('Certificate._identifier_tnauth_chk() endedt with %s', result)
        return result

    def _identifer_tnauth_list(self, identifier_dic: Dict[str, str], tnauthlist: List[str]):
        """ compare identifiers and check if each san is in identifer list """
        self.logger.debug('Certificate._identifer_tnauth_list()')

        identifier_status = []
        # reload identifiers (case senetive)
        try:
            identifiers = json.loads(identifier_dic['identifiers'])
        except Exception:
            identifiers = []

        if tnauthlist and not identifier_dic:
            identifier_status.append(False)
        elif identifiers and tnauthlist:
            for identifier in identifiers:
                identifier_status.append(self._identifier_tnauth_chk(identifier, tnauthlist))
        else:
            identifier_status.append(False)

        self.logger.debug('Certificate._identifer_tnauth_list() ended with %s', identifier_status)
        return identifier_status

    def _info(self, certificate_name: str, flist: List[str] = ('name', 'csr', 'cert', 'order__name')) -> Dict[str, str]:
        """ get certificate from database """
        self.logger.debug('Certificate._info(%s)', certificate_name)
        try:
            result = self.dbstore.certificate_lookup('name', certificate_name, flist)
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Certificate._info(): %s', err_)
            result = None
        return result

    def _expirydate_assume(self, cert: Dict[str, str], timestamp: int, to_be_cleared: bool) -> bool:
        """ assume expiry date """
        self.logger.debug('Certificate._expirydate_assume()')

        if 'csr' in cert and cert['csr']:
            # cover cases for enrollments in flight
            # we assume that a CSR should turn int a cert within two weeks
            if 'created_at' in cert:
                created_at_uts = date_to_uts_utc(cert['created_at'])
                if 0 < created_at_uts < timestamp - (14 * 86400):
                    to_be_cleared = True
            else:
                # this scneario should never been happen so lets be careful and not clear it
                to_be_cleared = False
        else:
            # no csr and no cert - to be cleared
            to_be_cleared = True

        self.logger.debug('Certificate._expirydate_assume() ended')
        return to_be_cleared

    def _expiredate_get(self, cert: Dict[str, str], timestamp: int, to_be_cleared: bool) -> bool:
        """ get expirey date from certificate """
        self.logger.debug('Certificate._expiredate_get()')

        # in case cert_expiry in table is 0 try to get it from cert
        if cert['expire_uts'] == 0:
            if 'cert_raw' in cert and cert['cert_raw']:
                # get expiration from certificate
                (issue_uts, expire_uts) = cert_dates_get(self.logger, cert['cert_raw'])
                if 0 < expire_uts < timestamp:
                    # returned date is other than 0 and lower than given timestamp
                    cert['issue_uts'] = issue_uts
                    cert['expire_uts'] = expire_uts
                    to_be_cleared = True
            else:
                to_be_cleared = self._expirydate_assume(cert, timestamp, to_be_cleared)
        else:
            # expired based on expire_uts from db
            to_be_cleared = True

        self.logger.debug('Certificate._expiredate_get() ended with: to_be_cleared:  %s', to_be_cleared)
        return to_be_cleared

    def _invalidation_check(self, cert: Dict[str, str], timestamp: int, purge: bool = False):
        """ check if cert must be invalidated """
        if 'name' in cert:
            self.logger.debug('Certificate._invalidation_check(%s)', cert['name'])
        else:
            self.logger.debug('Certificate._invalidation_check()')

        to_be_cleared = False

        if cert and 'name' in cert:
            if 'cert' in cert and cert['cert'] and 'removed by' in cert['cert'].lower():
                if purge:
                    # skip entries which had been cleared before cert[cert] check is needed to cover corner cases
                    to_be_cleared = True

            elif 'expire_uts' in cert:
                # get expiry date from either dictionary or certificate
                to_be_cleared = self._expiredate_get(cert, timestamp, to_be_cleared)
            else:
                # this scneario should never been happen so lets be careful and not clear it
                to_be_cleared = False
        else:
            # entries without a cert-name can be to_be_cleared
            to_be_cleared = True

        if 'name' in cert:
            self.logger.debug('Certificate._invalidation_check(%s) ended with %s', cert['name'], to_be_cleared)
        else:
            self.logger.debug('Certificate._invalidation_check() ended with %s', to_be_cleared)

        return (to_be_cleared, cert)

    def _order_update(self, data_dic: Dict[str, str]):
        """ update order based on ordername """
        self.logger.debug('Certificate._order_update(%s)', data_dic)
        try:
            self.dbstore.order_update(data_dic)
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Certificate._order_update(): %s', err_)

    def _revocation_reason_check(self, reason: str) -> str:
        """ check reason """
        self.logger.debug('Certificate._revocation_reason_check(%s)', reason)

        # taken from https://tools.ietf.org/html/rfc5280#section-5.3.1
        allowed_reasons = {
            0: 'unspecified',
            1: 'keyCompromise',
            # 2: 'cACompromise',
            3: 'affiliationChanged',
            4: 'superseded',
            5: 'cessationOfOperation',
            6: 'certificateHold',
            # 8: 'removeFromCRL',
            # 9: 'privilegeWithdrawn',
            # 10: 'aACompromise'
        }

        result = allowed_reasons.get(reason, None)
        self.logger.debug('Certificate._revocation_reason_check() ended with %s', result)
        return result

    def _revocation_request_validate(self, account_name: str, payload: Dict[str, str]) -> Tuple[int, str]:
        """ check revocaton request for consistency"""
        self.logger.debug('Certificate._revocation_request_validate(%s)', account_name)

        # set a value to avoid that we are returning none by accident
        code = 400
        error = None
        if 'reason' in payload:
            # check revocatoin reason if we get one
            rev_reason = self._revocation_reason_check(payload['reason'])
            # successful
            if not rev_reason:
                error = self.err_msg_dic['badrevocationreason']
        else:
            # set revocation reason to unspecified
            rev_reason = 'unspecified'

        if rev_reason:
            # check if the account issued the certificate and return the order name
            if 'certificate' in payload:
                order_name = self._account_check(account_name, payload['certificate'])
            else:
                order_name = None

            error = rev_reason
            if order_name:
                # check if the account holds the authorization for the identifiers
                auth_chk = self._authorization_check(order_name, payload['certificate'])
                if auth_chk:
                    # all good set code to 200
                    code = 200
                else:
                    error = self.err_msg_dic['unauthorized']

        self.logger.debug('Certificate._revocation_request_validate() ended with: %s, %s', code, error)
        return (code, error)

    def _store_cert(self, certificate_name: str, certificate: str, raw: str, issue_uts: int = 0, expire_uts: int = 0, poll_identifier: str = None) -> int:
        """ get key for a specific account id """
        self.logger.debug('Certificate._store_cert(%s)', certificate_name)

        renewal_info_hex = self._renewal_info_get(certificate)
        serial = cert_serial_get(self.logger, raw, hexformat=True)
        aki = cert_aki_get(self.logger, raw)

        data_dic = {'cert': certificate, 'name': certificate_name, 'cert_raw': raw, 'issue_uts': issue_uts, 'expire_uts': expire_uts, 'poll_identifier': poll_identifier, 'renewal_info': renewal_info_hex, 'serial': serial, 'aki': aki}
        try:
            cert_id = self.dbstore.certificate_add(data_dic)
        except Exception as err_:
            cert_id = None
            self.logger.critical('acme2certifier database error in Certificate._store_cert(): %s', err_)
        self.logger.debug('Certificate._store_cert(%s) ended', cert_id)
        return cert_id

    def _store_cert_error(self, certificate_name: str, error: str, poll_identifier: str) -> int:
        """ get key for a specific account id """
        self.logger.debug('Certificate._store_cert_error(%s)', certificate_name)
        data_dic = {'error': error, 'name': certificate_name, 'poll_identifier': poll_identifier}
        try:
            cert_id = self.dbstore.certificate_add(data_dic)
        except Exception as err_:
            cert_id = None
            self.logger.critical('acme2certifier database error in Certificate._store_cert(): %s', err_)
        self.logger.debug('Certificate._store_cert_error(%s) ended', cert_id)
        return cert_id

    def _tnauth_identifier_check(self, identifier_dic: Dict[str, str]) -> int:
        """ check if we have an tnauthlist_identifier """
        self.logger.debug('Certificate._tnauth_identifier_check()')
        # check if we have a tnauthlist identifier
        tnauthlist_identifer_in = False
        if identifier_dic:
            for identifier in identifier_dic:
                if 'type' in identifier:
                    if identifier['type'].lower() == 'tnauthlist':
                        tnauthlist_identifer_in = True
        self.logger.debug('Certificate._tnauth_identifier_check() ended with: %s', tnauthlist_identifer_in)
        return tnauthlist_identifer_in

    def certlist_search(self, key: str, value: str, vlist: List[str] = ('name', 'csr', 'cert', 'order__name')) -> Dict[str, str]:
        """ get certificate from database """
        self.logger.debug('Certificate.certlist_search(%s: %s)', key, value)
        try:
            result = self.dbstore.certificates_search(key, value, vlist)
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Certificate.certlist_search(): %s', err_)
            result = None
        return result

    def _cleanup(self, report_list: List[str], timestamp: int, purge: bool):
        """ cleanup  """
        self.logger.debug('Certificate.cleanup(%s,%s)', timestamp, purge)
        if not purge:
            # we are just modifiying data
            for cert in report_list:
                data_dic = {
                    'name': cert['name'],
                    'expire_uts': cert['expire_uts'],
                    'issue_uts': cert['issue_uts'],
                    'cert': f'removed by certificates.cleanup() on {uts_to_date_utc(timestamp)}',
                    'cert_raw': cert['cert_raw']
                }
                try:
                    self.dbstore.certificate_add(data_dic)
                except Exception as err_:
                    self.logger.critical('acme2certifier database error in Certificate.cleanup() add: %s', err_)
        else:
            # delete entries from certificates table
            for cert in report_list:
                try:
                    self.dbstore.certificate_delete('id', cert['id'])
                except Exception as err_:
                    self.logger.critical('acme2certifier database error in Certificate.cleanup() delete: %s', err_)

        self.logger.debug('Certificate.cleanup() ended')

    def cleanup(self, timestamp: int = None, purge: bool = False) -> Tuple[List[str], List[str]]:
        """ cleanup routine to shrink table-size """
        self.logger.debug('Certificate.cleanup(%s,%s)', timestamp, purge)

        field_list = ['id', 'name', 'expire_uts', 'issue_uts', 'cert', 'cert_raw', 'csr', 'created_at', 'order__id', 'order__name']

        # get expired certificates
        try:
            certificate_list = self.dbstore.certificates_search('expire_uts', timestamp, field_list, '<=')
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Certificate.cleanup() search: %s', err_)
            certificate_list = []

        report_list = []
        for cert in certificate_list:
            (to_be_cleared, cert) = self._invalidation_check(cert, timestamp, purge)

            if to_be_cleared:
                report_list.append(cert)

        # cleanup
        self._cleanup(report_list, timestamp, purge)

        self.logger.debug('Certificate.cleanup() ended with: %s certs', len(report_list))
        return (field_list, report_list)

    def _dates_update(self, cert: Dict[str, str]):
        """ update issue and expiry date with date from certificate """
        self.logger.debug('Certificate._dates_update()')

        if 'issue_uts' in cert and 'expire_uts' in cert:
            if cert['issue_uts'] == 0 and cert['expire_uts'] == 0:
                if cert['cert_raw']:
                    (issue_uts, expire_uts) = cert_dates_get(self.logger, cert['cert_raw'])
                    if issue_uts or expire_uts:
                        self._store_cert(cert['name'], cert['cert'], cert['cert_raw'], issue_uts, expire_uts)

        self.logger.debug('Certificate._dates_update() ended')

    def dates_update(self):
        """ scan certificates and update issue/expiry date """
        self.logger.debug('Certificate.dates_update()')

        with Certificate(self.debug, None, self.logger) as certificate:
            cert_list = certificate.certlist_search('issue_uts', 0, vlist=('id', 'name', 'cert', 'cert_raw', 'issue_uts', 'expire_uts'))
            self.logger.debug('Got {%s} certificates to be updated...', len(cert_list))
            for cert in cert_list:
                self._dates_update(cert)

        self.logger.debug('Certificate.dates_update() ended')

    def enroll_and_store(self, certificate_name: str, csr: str, order_name: str = None) -> Tuple[str, str]:
        """ check csr and trigger enrollment """
        self.logger.debug('Certificate.enroll_and_store(%s, %s)', certificate_name, order_name)

        # check csr against order
        csr_check_result = self._csr_check(certificate_name, csr)

        # only continue if self.csr_check returned True
        if csr_check_result:
            twrv = ThreadWithReturnValue(target=self._enroll_and_store, args=(certificate_name, csr, order_name))
            twrv.start()
            enroll_result = twrv.join(timeout=self.enrollment_timeout)
            if enroll_result:
                try:
                    (result, error, detail) = enroll_result
                except Exception as err_:
                    self.logger.error('acme2certifier database error in Certificate.enroll_and_store(): split of %s failed with err: %s', enroll_result, err_)
                    result = None
                    error = self.err_msg_dic['serverinternal']
                    detail = 'unexpected enrollment result'
            else:
                result = None
                error = 'timeout'
                detail = 'timeout'
        else:
            result = None
            error = self.err_msg_dic['badcsr']
            detail = 'CSR validation failed'

        self.logger.debug('Certificate.enroll_and_store() ended with: %s:%s', result, error)
        return (error, detail)

    def new_get(self, url: str) -> Dict[str, str]:
        """ get request """
        certificate_name = string_sanitize(self.logger, url.replace(f'{self.server_name}{self.path_dic["cert_path"]}', ''))
        self.logger.debug('Certificate.new_get(%s)', certificate_name)

        # fetch certificate dictionary from DB
        certificate_dic = self._info(certificate_name, ['name', 'csr', 'cert', 'order__name', 'order__status_id'])
        response_dic = {}
        if 'order__status_id' in certificate_dic:
            if certificate_dic['order__status_id'] == 5:
                # oder status is valid - download certificate
                if 'cert' in certificate_dic and certificate_dic['cert']:
                    response_dic['code'] = 200
                    # filter certificate and decode it
                    response_dic['data'] = certificate_dic['cert']
                    response_dic['header'] = {}
                    response_dic['header']['Content-Type'] = 'application/pem-certificate-chain'
                else:
                    response_dic['code'] = 500
                    response_dic['data'] = self.err_msg_dic['serverinternal']
            elif certificate_dic['order__status_id'] == 4:
                # order status is processing - ratelimiting
                response_dic['header'] = {'Retry-After': f'{self.retry_after}'}
                response_dic['code'] = 403
                response_dic['data'] = self.err_msg_dic['ratelimited']
            else:
                response_dic['code'] = 403
                response_dic['data'] = self.err_msg_dic['ordernotready']
        else:
            response_dic['code'] = 500
            response_dic['data'] = self.err_msg_dic['serverinternal']

        self.logger.debug('Certificate.new_get(%s) ended', response_dic['code'])
        return response_dic

    def new_post(self, content: str) -> Dict[str, str]:
        """ post request """
        self.logger.debug('Certificate.new_post()')

        response_dic = {}
        # check message
        (code, message, detail, protected, _payload, _account_name) = self.message.check(content)
        if code == 200:
            if 'url' in protected:
                response_dic = self.new_get(protected['url'])
                if response_dic['code'] in (400, 403, 400, 500):
                    code = response_dic['code']
                    message = response_dic['data']
                    detail = None
            else:
                response_dic['code'] = code = 400
                # pylint: disable=w0612, w0622
                response_dic['data'] = self.err_msg_dic['malformed']
                detail = 'url missing in protected header'

        # prepare/enrich response
        status_dic = {'code': code, 'type': message, 'detail': detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)

        # depending on the response the content of responsedic['data'] can be either string or dict
        # data will get serialzed
        if isinstance(response_dic['data'], dict):
            response_dic['data'] = json.dumps(response_dic['data'])

        # cover cornercase - not sure if we ever run into such situation
        if 'code' in response_dic:
            result = response_dic['code']
        else:
            result = 'no code found'

        self.logger.debug('Certificate.new_post() ended with: %s', result)
        return response_dic

    def revoke(self, content: str) -> Dict[str, str]:
        """ revoke request """
        self.logger.debug('Certificate.revoke()')

        response_dic = {}
        # check message
        (code, message, detail, _protected, payload, account_name) = self.message.check(content)

        if code == 200:
            if 'certificate' in payload:
                (code, error) = self._revocation_request_validate(account_name, payload)
                if code == 200:
                    # revocation starts here
                    # revocation reason is stored in error variable
                    rev_date = uts_to_date_utc(uts_now())
                    with self.cahandler(self.debug, self.logger) as ca_handler:
                        (code, message, detail) = ca_handler.revoke(payload['certificate'], error, rev_date)
                else:
                    message = error
                    detail = None

            else:
                # message could not get decoded
                code = 400
                message = self.err_msg_dic['malformed']
                detail = 'certificate not found'

        # prepare/enrich response
        status_dic = {'code': code, 'type': message, 'detail': detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)

        self.logger.debug('Certificate.revoke() ended with: %s', response_dic)
        return response_dic

    def poll(self, certificate_name: str, poll_identifier: str, csr: str, order_name: str) -> int:
        """ try to fetch a certificate from CA and store it into database """
        self.logger.debug('Certificate.poll(%s: %s)', certificate_name, poll_identifier)

        with self.cahandler(self.debug, self.logger) as ca_handler:
            (error, certificate, certificate_raw, poll_identifier, rejected) = ca_handler.poll(certificate_name, poll_identifier, csr)
            if certificate:
                # get issuing and expiration date
                (issue_uts, expire_uts) = cert_dates_get(self.logger, certificate_raw)
                # update certificate record in database
                _result = self._store_cert(certificate_name, certificate, certificate_raw, issue_uts, expire_uts)
                # update order status to 5 (valid)
                try:
                    self.dbstore.order_update({'name': order_name, 'status': 'valid'})
                except Exception as err_:
                    self.logger.critical('acme2certifier database error in Certificate.poll(): %s', err_)
            else:
                # store error message for later analysis
                self._store_cert_error(certificate_name, error, poll_identifier)
                _result = None
                if rejected:
                    try:
                        self.dbstore.order_update({'name': order_name, 'status': 'invalid'})
                    except Exception as err_:
                        self.logger.critical('acme2certifier database error in Certificate.poll(): %s', err_)
        self.logger.debug('Certificate.poll(%s: %s)', certificate_name, poll_identifier)
        return _result

    def store_csr(self, order_name: str, csr: str, header_info: str) -> str:
        """ store csr into database """
        self.logger.debug('Certificate.store_csr(%s)', order_name)

        certificate_name = generate_random_string(self.logger, 12)
        data_dic = {'order': order_name, 'csr': csr, 'name': certificate_name, 'header_info': header_info}
        try:
            self.dbstore.certificate_add(data_dic)
        except Exception as err_:
            self.logger.critical('Database error in Certificate.store_csr(): %s', err_)
        self.logger.debug('Certificate.store_csr() ended')
        return certificate_name
