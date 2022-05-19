#!/usr/bin/python
# -*- coding: utf-8 -*-
# pylint: disable=c0209, e5110, r0902, r0912, r0915
""" certificate class """
from __future__ import print_function
import json
from acme_srv.helper import b64_url_recode, generate_random_string, cert_san_get, cert_extensions_get, hooks_load, uts_now, uts_to_date_utc, date_to_uts_utc, load_config, csr_san_get, csr_extensions_get, cert_dates_get, ca_handler_load
from acme_srv.db_handler import DBstore
from acme_srv.message import Message
from acme_srv.threadwithreturnvalue import ThreadWithReturnValue


class Certificate(object):
    """ CA  handler """

    def __init__(self, debug=None, srv_name=None, logger=None):
        self.debug = debug
        self.server_name = srv_name
        self.logger = logger
        self.cahandler = None
        self.dbstore = DBstore(self.debug, self.logger)
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

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _account_check(self, account_name, certificate):
        """ check account """
        self.logger.debug('Certificate.issuer_check()')
        try:
            result = self.dbstore.certificate_account_check(account_name, b64_url_recode(self.logger, certificate))
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Certificate._account_check(): {0}'.format(err_))
            result = None
        return result

    def _authorization_check(self, order_name, certificate):
        """ check if an acount holds authorization for all identifiers = SANs in the certificate """
        self.logger.debug('Certificate._authorization_check()')

        # empty list of statuses
        identifier_status = []

        # get identifiers for order
        try:
            identifier_dic = self.dbstore.order_lookup('name', order_name, ['identifiers'])
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Certificate._authorization_check(): {0}'.format(err_))
            identifier_dic = {}

        if identifier_dic and 'identifiers' in identifier_dic:
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
                    self.logger.warning('Certificate._authorization_check() error while loading parsing certifcate. Error: {0}'.format(err_))
            else:
                try:
                    # get sans
                    san_list = cert_san_get(self.logger, certificate)
                    identifier_status = self._identifer_status_list(identifiers, san_list)
                except Exception as err_:
                    # enough to set identifier_list as empty list
                    identifier_status = []
                    self.logger.warning('Certificate._authorization_check() error while loading parsing certifcate. Error: {0}'.format(err_))

        result = False
        if identifier_status and False not in identifier_status:
            result = True

        self.logger.debug('Certificate._authorization_check() ended with {0}'.format(result))
        return result

    def _cert_reusage_check(self, csr):
        """ check if an existing certificate an be reused """
        self.logger.debug('Certificate._cert_reusage_check({0})'.format(self.cert_reusage_timeframe))

        try:
            result_dic = self.dbstore.certificates_search('csr', csr, ('cert', 'cert_raw', 'expire_uts', 'issue_uts', 'created_at', 'id'))
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Certificate._cert_reusage_check(): {0}'.format(err_))
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
                    self.logger.error('acme2certifier date_to_uts_utc() error in Certificate._cert_reusage_check(): id:{0}/created_at:{1}'.format(certificate['id'], certificate['created_at']))
                    uts_create = 0

                # check if there certificates within reusage timeframe
                if certificate['cert_raw'] and certificate['cert'] and uts - self.cert_reusage_timeframe <= uts_create:
                    # exclude expired certificates
                    if uts <= certificate['expire_uts']:
                        cert = certificate['cert']
                        cert_raw = certificate['cert_raw']
                        message = 'reused certificate from id: {0}'.format(certificate['id'])
                        break

        self.logger.debug('Certificate._cert_reusage_check() ended with {0}'.format(message))
        return(None, cert, cert_raw, message)

    def _config_load(self):
        """" load config from file """
        self.logger.debug('Certificate._config_load()')
        config_dic = load_config()
        if 'Order' in config_dic:
            self.tnauthlist_support = config_dic.getboolean('Order', 'tnauthlist_support', fallback=False)

        # load ca_handler according to configuration
        ca_handler_module = ca_handler_load(self.logger, config_dic)

        if ca_handler_module:
            # store handler in variable
            self.cahandler = ca_handler_module.CAhandler
        else:
            self.logger.critical('Certificate._config_load(): No ca_handler loaded')

        # load hooks according to configuration
        hooks_module = hooks_load(self.logger, config_dic)
        if hooks_module:
            try:
                # store handler in variable
                self.hooks = hooks_module.Hooks(self.logger)
            except Exception as err:
                self.logger.critical('Certificate._config_load(): Hooks could not be loaded: {0}'.format(err))

            self.ignore_pre_hook_failure = config_dic.getboolean('Hooks', 'ignore_pre_hook_failure', fallback=False)
            self.ignore_post_hook_failure = config_dic.getboolean('Hooks', 'ignore_post_hook_failure', fallback=True)
            self.ignore_success_hook_failure = config_dic.getboolean('Hooks', 'ignore_success_hook_failure', fallback=False)

        if 'Certificate' in config_dic:
            if 'cert_reusage_timeframe' in config_dic['Certificate']:
                try:
                    self.cert_reusage_timeframe = int(config_dic['Certificate']['cert_reusage_timeframe'])
                except Exception as err_:
                    self.logger.error('acme2certifier Certificate._config_load() cert_reusage_timout parsing error: {0}'.format(err_))
            if 'enrollment_timeout' in config_dic['Certificate']:
                try:
                    self.enrollment_timeout = int(config_dic['Certificate']['enrollment_timeout'])
                except Exception as err_:
                    self.logger.error('acme2certifier Certificate._config_load() enrollment_timeout parsing error: {0}'.format(err_))

        if 'Directory' in config_dic:
            if 'url_prefix' in config_dic['Directory']:
                self.path_dic = {k: config_dic['Directory']['url_prefix'] + v for k, v in self.path_dic.items()}

        self.logger.debug('ca_handler: {0}'.format(ca_handler_module))
        self.logger.debug('Certificate._config_load() ended.')

    def _csr_check(self, certificate_name, csr):
        """ compare csr extensions against order """
        self.logger.debug('Certificate._csr_check()')

        # fetch certificate dictionary from DB
        certificate_dic = self._info(certificate_name)
        self.logger.debug('Certificate._info() ended with:{0}'.format(certificate_dic))

        # empty list of statuses
        identifier_status = []

        if 'order' in certificate_dic:
            # get identifiers for order
            try:
                identifier_dic = self.dbstore.order_lookup('name', certificate_dic['order'], ['identifiers'])
            except Exception as err_:
                self.logger.critical('acme2certifier database error in Certificate._csr_check(): {0}'.format(err_))
                identifier_dic = {}

            if identifier_dic and 'identifiers' in identifier_dic:
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
                        self.logger.warning('Certificate._csr_check() error while parsing csr.\nerror: {0}'.format(err_))
                else:
                    # get sans and compare identifiers against san
                    try:
                        san_list = csr_san_get(self.logger, csr)
                        identifier_status = self._identifer_status_list(identifiers, san_list)
                    except Exception as err_:
                        identifier_status = []
                        self.logger.warning('Certificate._csr_check() error while checking csr.\nerror: {0}'.format(err_))

        csr_check_result = False

        if identifier_status and False not in identifier_status:
            csr_check_result = True

        self.logger.debug('Certificate._csr_check() ended with {0}'.format(csr_check_result))
        return csr_check_result

    def _enroll_and_store(self, certificate_name, csr, order_name=None):
        """ enroll and store certificate """
        self.logger.debug('Certificate._enroll_and_store({0}, {1}, {2})'.format(certificate_name, order_name, csr))

        detail = None
        error = None

        if self.hooks:
            try:
                self.hooks.pre_hook(certificate_name, order_name, csr)
                self.logger.debug('Certificate._enroll_and_store(): pre_hook successful')
            except Exception as err:
                self.logger.error('Certificate._enroll_and_store(): pre_hook exception: {0}'.format(err))
                if not self.ignore_pre_hook_failure:
                    return (None, 'pre_hook_error', str(err))

        with self.cahandler(self.debug, self.logger) as ca_handler:
            if self.cert_reusage_timeframe:
                (error, certificate, certificate_raw, poll_identifier) = self._cert_reusage_check(csr)
            else:
                certificate = None
                certificate_raw = None

            if not certificate or not certificate_raw:
                self.logger.debug('Certificate._enroll_and_store(): trigger enrollment')
                (error, certificate, certificate_raw, poll_identifier) = ca_handler.enroll(csr)
            else:
                self.logger.info('Certificate._enroll_and_store(): reuse existing certificate')

            if certificate:
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
                            self.logger.error('Certificate._enroll_and_store: success_hook exception: {0}'.format(err))
                            if not self.ignore_success_hook_failure:
                                return (None, 'success_hook_error', str(err))

                except Exception as err_:
                    result = None
                    self.logger.critical('acme2certifier database error in Certificate._enroll_and_store(): {0}'.format(err_))
            else:
                result = None
                self.logger.error('acme2certifier enrollment error: {0}'.format(error))
                # store error message for later analysis
                try:
                    if not poll_identifier:
                        self.logger.debug('Certificate._enroll_and_store(): invalidating order as there is no certificate and no poll_identifier: {0}/{1}'.format(error, order_name))
                        self._order_update({'name': order_name, 'status': 'invalid'})
                    self._store_cert_error(certificate_name, error, poll_identifier)
                except Exception as err_:
                    result = None
                    self.logger.critical('acme2certifier database error in Certificate._enroll_and_store() _store_cert_error: {0}'.format(err_))

                # cover polling cases
                if poll_identifier:
                    detail = poll_identifier
                else:
                    error = 'urn:ietf:params:acme:error:serverInternal'

        if self.hooks:
            try:
                self.hooks.post_hook(certificate_name, order_name, csr, error)
                self.logger.debug('Certificate._enroll_and_store(): post_hook successful')
            except Exception as err:
                self.logger.error('Certificate._enroll_and_store(): post_hook exception: {0}'.format(err))
                if not self.ignore_post_hook_failure:
                    return (None, 'post_hook_error', str(err))

        self.logger.debug('Certificate._enroll_and_store() ended with: {0}:{1}'.format(result, error))
        return (result, error, detail)

    def _identifer_status_list(self, identifiers, san_list):
        """ compare identifiers and check if each san is in identifer list """
        self.logger.debug('Certificate._identifer_status_list()')

        identifier_status = []
        for san in san_list:
            san_is_in = False
            try:
                (cert_type, cert_value) = san.lower().split(':')
            except Exception:
                cert_type = None
                cert_value = None

            if cert_type and cert_value:
                for identifier in identifiers:
                    if 'type' in identifier:
                        if (identifier['type'].lower() == cert_type and identifier['value'].lower() == cert_value):
                            san_is_in = True
                            break
            self.logger.debug('SAN check for {0} against identifiers returned {1}'.format(san.lower(), san_is_in))
            identifier_status.append(san_is_in)

        if not identifier_status:
            identifier_status.append(False)

        self.logger.debug('Certificate._identifer_status_list() ended with {0}'.format(identifier_status))
        return identifier_status

    def _identifer_tnauth_list(self, identifier_dic, tnauthlist):
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
                # get the tnauthlist identifier
                if 'type' in identifier and identifier['type'].lower() == 'tnauthlist':
                    # check if tnauthlist extension is in extension list
                    if 'value' in identifier and identifier['value'] in tnauthlist:
                        identifier_status.append(True)
                    else:
                        identifier_status.append(False)
                else:
                    identifier_status.append(False)
        else:
            identifier_status.append(False)

        self.logger.debug('Certificate._identifer_status_list() ended with {0}'.format(identifier_status))
        return identifier_status

    def _info(self, certificate_name, flist=('name', 'csr', 'cert', 'order__name')):
        """ get certificate from database """
        self.logger.debug('Certificate._info({0})'.format(certificate_name))
        try:
            result = self.dbstore.certificate_lookup('name', certificate_name, flist)
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Certificate._info(): {0}'.format(err_))
            result = None
        return result

    def _invalidation_check(self, cert, timestamp, purge=False):
        """ check if cert must be invalidated """
        if 'name' in cert:
            self.logger.debug('Certificate._invalidation_check({0})'.format(cert['name']))
        else:
            self.logger.debug('Certificate._invalidation_check()')

        to_be_cleared = False

        if cert and 'name' in cert:
            if 'cert' in cert and cert['cert'] and 'removed by' in cert['cert'].lower():
                if not purge:
                    # skip entries which had been cleared before cert[cert] check is needed to cover corner cases
                    to_be_cleared = False
                else:
                    # purge entries
                    to_be_cleared = True

            elif 'expire_uts' in cert:
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

                else:
                    # expired based on expire_uts from db
                    to_be_cleared = True
            else:
                # this scneario should never been happen so lets be careful and not clear it
                to_be_cleared = False
        else:
            # entries without a cert-name can be to_be_cleared
            to_be_cleared = True

        if 'name' in cert:
            self.logger.debug('Certificate._invalidation_check({0}) ended with {1}'.format(cert['name'], to_be_cleared))
        else:
            self.logger.debug('Certificate._invalidation_check() ended with {0}'.format(to_be_cleared))
        return (to_be_cleared, cert)

    def _order_update(self, data_dic):
        """ update order based on ordername """
        self.logger.debug('Certificate._order_update({0})'.format(data_dic))
        try:
            self.dbstore.order_update(data_dic)
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Certificate._order_update(): {0}'.format(err_))

    def _revocation_reason_check(self, reason):
        """ check reason """
        self.logger.debug('Certificate._revocation_reason_check({0})'.format(reason))

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
        self.logger.debug('Certificate._revocation_reason_check() ended with {0}'.format(result))
        return result

    def _revocation_request_validate(self, account_name, payload):
        """ check revocaton request for consistency"""
        self.logger.debug('Certificate._revocation_request_validate({0})'.format(account_name))

        # set a value to avoid that we are returning none by accident
        code = 400
        error = None
        if 'reason' in payload:
            # check revocatoin reason if we get one
            rev_reason = self._revocation_reason_check(payload['reason'])
            # successful
            if not rev_reason:
                error = 'urn:ietf:params:acme:error:badRevocationReason'
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
                    error = 'urn:ietf:params:acme:error:unauthorized'

        self.logger.debug('Certificate._revocation_request_validate() ended with: {0}, {1}'.format(code, error))
        return (code, error)

    def _store_cert(self, certificate_name, certificate, raw, issue_uts=0, expire_uts=0, poll_identifier=None):
        """ get key for a specific account id """
        self.logger.debug('Certificate._store_cert({0})'.format(certificate_name))
        data_dic = {'cert': certificate, 'name': certificate_name, 'cert_raw': raw, 'issue_uts': issue_uts, 'expire_uts': expire_uts, 'poll_identifier': poll_identifier}
        try:
            cert_id = self.dbstore.certificate_add(data_dic)
        except Exception as err_:
            cert_id = None
            self.logger.critical('acme2certifier database error in Certificate._store_cert(): {0}'.format(err_))
        self.logger.debug('Certificate._store_cert({0}) ended'.format(cert_id))
        return cert_id

    def _store_cert_error(self, certificate_name, error, poll_identifier):
        """ get key for a specific account id """
        self.logger.debug('Certificate._store_cert_error({0})'.format(certificate_name))
        data_dic = {'error': error, 'name': certificate_name, 'poll_identifier': poll_identifier}
        try:
            cert_id = self.dbstore.certificate_add(data_dic)
        except Exception as err_:
            cert_id = None
            self.logger.critical('acme2certifier database error in Certificate._store_cert(): {0}'.format(err_))
        self.logger.debug('Certificate._store_cert_error({0}) ended'.format(cert_id))
        return cert_id

    def _tnauth_identifier_check(self, identifier_dic):
        """ check if we have an tnauthlist_identifier """
        self.logger.debug('Certificate._tnauth_identifier_check()')
        # check if we have a tnauthlist identifier
        tnauthlist_identifer_in = False
        if identifier_dic:
            for identifier in identifier_dic:
                if 'type' in identifier:
                    if identifier['type'].lower() == 'tnauthlist':
                        tnauthlist_identifer_in = True
        self.logger.debug('Certificate._tnauth_identifier_check() ended with: {0}'.format(tnauthlist_identifer_in))
        return tnauthlist_identifer_in

    def certlist_search(self, key, value, vlist=('name', 'csr', 'cert', 'order__name')):
        """ get certificate from database """
        self.logger.debug('Certificate.certlist_search({0}: {1})'.format(key, value))
        try:
            result = self.dbstore.certificates_search(key, value, vlist)
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Certificate.certlist_search(): {0}'.format(err_))
            result = None
        return result

    def cleanup(self, timestamp=None, purge=False):
        """ cleanup routine to shrink table-size """
        self.logger.debug('Certificate.cleanup({0},{1})'.format(timestamp, purge))

        field_list = ['id', 'name', 'expire_uts', 'issue_uts', 'cert', 'cert_raw', 'csr', 'created_at', 'order__id', 'order__name']

        # get expired certificates
        try:
            certificate_list = self.dbstore.certificates_search('expire_uts', timestamp, field_list, '<=')
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Certificate.cleanup() search: {0}'.format(err_))
            certificate_list = []

        report_list = []
        for cert in certificate_list:
            (to_be_cleared, cert) = self._invalidation_check(cert, timestamp, purge)

            if to_be_cleared:
                report_list.append(cert)

        if not purge:
            # we are just modifiying data
            for cert in report_list:
                data_dic = {
                    'name': cert['name'],
                    'expire_uts': cert['expire_uts'],
                    'issue_uts': cert['issue_uts'],
                    'cert': 'removed by certificates.cleanup() on {0} '.format(uts_to_date_utc(timestamp)),
                    'cert_raw': cert['cert_raw']
                }
                try:
                    self.dbstore.certificate_add(data_dic)
                except Exception as err_:
                    self.logger.critical('acme2certifier database error in Certificate.cleanup() add: {0}'.format(err_))
        else:
            # delete entries from certificates table
            for cert in report_list:
                try:
                    self.dbstore.certificate_delete('id', cert['id'])
                except Exception as err_:
                    self.logger.critical('acme2certifier database error in Certificate.cleanup() delete: {0}'.format(err_))
        self.logger.debug('Certificate.cleanup() ended with: {0} certs'.format(len(report_list)))
        return (field_list, report_list)

    def dates_update(self):
        """ scan certificates and update issue/expiry date """
        self.logger.debug('Certificate.certificate_dates_update()')

        with Certificate(self.debug, None, self.logger) as certificate:
            cert_list = certificate.certlist_search('issue_uts', 0, vlist=('id', 'name', 'cert', 'cert_raw', 'issue_uts', 'expire_uts'))
            self.logger.debug('Got {0} certificates to be updated...'.format(len(cert_list)))
            for cert in cert_list:
                if 'issue_uts' in cert and 'expire_uts' in cert:
                    if cert['issue_uts'] == 0 and cert['expire_uts'] == 0:
                        if cert['cert_raw']:
                            (issue_uts, expire_uts) = cert_dates_get(self.logger, cert['cert_raw'])
                            if issue_uts or expire_uts:
                                self._store_cert(cert['name'], cert['cert'], cert['cert_raw'], issue_uts, expire_uts)

    def enroll_and_store(self, certificate_name, csr, order_name=None):
        """ check csr and trigger enrollment """
        self.logger.debug('Certificate.enroll_and_store({0},{1})'.format(certificate_name, order_name))

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
                    self.logger.error('acme2certifier database error in Certificate.enroll_and_store(): split of {0} failed with err: {1}'.format(enroll_result, err_))
                    result = None
                    error = 'urn:ietf:params:acme:error:serverInternal'
                    detail = 'unexpected enrollment result'
            else:
                result = None
                error = 'timeout'
                detail = 'timeout'
        else:
            result = None
            error = 'urn:ietf:params:acme:badCSR'
            detail = 'CSR validation failed'

        self.logger.debug('Certificate.enroll_and_store() ended with: {0}:{1}'.format(result, error))
        return (error, detail)

    def new_get(self, url):
        """ get request """
        self.logger.debug('Certificate.new_get({0})'.format(url))
        certificate_name = url.replace('{0}{1}'.format(self.server_name, self.path_dic['cert_path']), '')

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
                    response_dic['data'] = 'urn:ietf:params:acme:error:serverInternal'
            elif certificate_dic['order__status_id'] == 4:
                # order status is processing - ratelimiting
                response_dic['header'] = {'Retry-After': '{0}'.format(self.retry_after)}
                response_dic['code'] = 403
                response_dic['data'] = 'urn:ietf:params:acme:error:rateLimited'
            else:
                response_dic['code'] = 403
                response_dic['data'] = 'urn:ietf:params:acme:error:orderNotReady'
        else:
            response_dic['code'] = 500
            response_dic['data'] = 'urn:ietf:params:acme:error:serverInternal'

        self.logger.debug('Certificate.new_get({0}) ended'.format(response_dic['code']))

        return response_dic

    def new_post(self, content):
        """ post request """
        self.logger.debug('Certificate.new_post({0})')

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
                response_dic['data'] = message = 'urn:ietf:params:acme:error:malformed'
                detail = 'url missing in protected header'

        # prepare/enrich response
        status_dic = {'code': code, 'status': message, 'detail': detail}
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

        self.logger.debug('Certificate.new_post() ended with: {0}'.format(result))
        return response_dic

    def revoke(self, content):
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
                message = 'urn:ietf:params:acme:error:malformed'
                detail = 'certificate not found'

        # prepare/enrich response
        status_dic = {'code': code, 'status': message, 'detail': detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)

        self.logger.debug('Certificate.revoke() ended with: {0}'.format(response_dic))
        return response_dic

    def poll(self, certificate_name, poll_identifier, csr, order_name):
        """ try to fetch a certificate from CA and store it into database """
        self.logger.debug('Certificate.poll({0}: {1})'.format(certificate_name, poll_identifier))

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
                    self.logger.critical('acme2certifier database error in Certificate.poll(): {0}'.format(err_))
            else:
                # store error message for later analysis
                self._store_cert_error(certificate_name, error, poll_identifier)
                _result = None
                if rejected:
                    try:
                        self.dbstore.order_update({'name': order_name, 'status': 'invalid'})
                    except Exception as err_:
                        self.logger.critical('acme2certifier database error in Certificate.poll(): {0}'.format(err_))
        self.logger.debug('Certificate.poll({0}: {1})'.format(certificate_name, poll_identifier))
        return _result

    def store_csr(self, order_name, csr):
        """ store csr into database """
        self.logger.debug('Certificate.store_csr({0})'.format(order_name))
        certificate_name = generate_random_string(self.logger, 12)
        data_dic = {'order': order_name, 'csr': csr, 'name': certificate_name}
        try:
            self.dbstore.certificate_add(data_dic)
        except Exception as err_:
            self.logger.critical('Database error in Certificate.store_csr(): {0}'.format(err_))
        self.logger.debug('Certificate.store_csr() ended')
        return certificate_name
