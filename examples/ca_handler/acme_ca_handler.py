# -*- coding: utf-8 -*-
""" generic ca handler for CAs supporting acme protocol """
from __future__ import print_function
# pylint: disable= e0401, w0105, w0212
import json
import textwrap
import base64
import os.path
from typing import Tuple, Dict
import requests
import josepy
from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from acme import client, messages
from acme_srv.db_handler import DBstore
from acme_srv.helper import load_config, b64_url_recode, parse_url, allowed_domainlist_check, header_info_field_validate, header_info_lookup, config_eab_profile_load, config_headerinfo_load

"""
Config file section:

[CAhandler]
# CA specific options
acme_url: https://some.acme/endpoint
acme_account: <account-id>
acme_keyfile: /path/to/privkey.json

"""


class CAhandler(object):
    """ EST CA  handler """

    def __init__(self, _debug: bool = False, logger: object = None):
        self.logger = logger
        self.url = None
        self.url_dic = {}
        self.keyfile = None
        self.key_size = 2048
        self.account = None
        self.email = None
        self.path_dic = {'directory_path': '/directory', 'acct_path': '/acme/acct/'}
        self.dbstore = DBstore(None, self.logger)
        self.allowed_domainlist = []
        self.eab_kid = None
        self.eab_hmac_key = None
        self.header_info_field = False
        self.eab_handler = None
        self.eab_profiling = False

    def __enter__(self):
        """ Makes CAhandler a Context Manager """
        if not self.url:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ close the connection at the end of the context """

    def _config_account_load(self, config_dic: Dict[str, str]):
        self.logger.debug('CAhandler._config_account_load()')

        if 'acme_keyfile' in config_dic['CAhandler']:
            self.keyfile = config_dic['CAhandler']['acme_keyfile']
        else:
            self.logger.error('CAhandler._config_load() configuration incomplete: "acme_keyfile" parameter is missing in config file')

        if 'acme_url' in config_dic['CAhandler']:
            self.url = config_dic['CAhandler']['acme_url']
            self.url_dic = parse_url(self.logger, self.url)
        else:
            self.logger.error('CAhandler._config_load() configuration incomplete: "acme_url" parameter is missing in config file')

        if 'acme_account' in config_dic['CAhandler']:
            self.account = config_dic['CAhandler']['acme_account']

        if 'account_path' in config_dic['CAhandler']:
            self.path_dic['acct_path'] = config_dic['CAhandler']['account_path']

        if 'acme_account_keysize' in config_dic['CAhandler']:
            self.key_size = config_dic['CAhandler']['acme_account_keysize']

        if 'acme_account_email' in config_dic['CAhandler']:
            self.email = config_dic['CAhandler']['acme_account_email']

        self.logger.debug('CAhandler._config_account_load() ended')

    def _config_parameters_load(self, config_dic: Dict[str, str]):
        """" load eab config """
        self.logger.debug('CAhandler._config_eab_load()')

        if 'directory_path' in config_dic['CAhandler']:
            self.path_dic['directory_path'] = config_dic['CAhandler']['directory_path']

        if 'allowed_domainlist' in config_dic['CAhandler']:
            try:
                self.allowed_domainlist = json.loads(config_dic['CAhandler']['allowed_domainlist'])
            except Exception as err:
                self.logger.error('CAhandler._config_load(): failed to parse allowed_domainlist: %s', err)

        if 'eab_kid' in config_dic['CAhandler']:
            self.eab_kid = config_dic['CAhandler']['eab_kid']

        if 'eab_hmac_key' in config_dic['CAhandler']:
            self.eab_hmac_key = config_dic['CAhandler']['eab_hmac_key']

        self.logger.debug('CAhandler._config_eab_load() ended')

    def _config_load(self):
        """" load config from file """
        self.logger.debug('CAhandler._config_load()')
        config_dic = load_config()
        if 'CAhandler' in config_dic:

            # load account configuration and paramters
            self._config_account_load(config_dic)
            self._config_parameters_load(config_dic)

            self.logger.debug('CAhandler._config_load() ended')
        else:
            self.logger.error('CAhandler._config_load() configuration incomplete: "CAhandler" section is missing in config file')

        # load profiling
        self.eab_profiling, self.eab_handler = config_eab_profile_load(self.logger, config_dic)
        # load header info
        self.header_info_field = config_headerinfo_load(self.logger, config_dic)

    def _challenge_filter(self, authzr: messages.AuthorizationResource, chall_type: str = 'http-01') -> messages.ChallengeBody:
        """ filter authorization for challenge """
        self.logger.debug('CAhandler._challenge_filter(%s)', chall_type)
        result = None
        for challenge in authzr.body.challenges:
            if challenge.chall.to_partial_json()['type'] == chall_type:
                result = challenge
                break
        if not result:
            self.logger.error('CAhandler._challenge_filter() ended. Could not find challenge of type %s', chall_type)

        return result

    def _challenge_store(self, challenge_name: str, challenge_content: str):
        """ store challenge into database """
        self.logger.debug('CAhandler._challenge_store(%s)', challenge_name)

        if challenge_name and challenge_content:
            data_dic = {'name': challenge_name, 'value1': challenge_content}
            # store challenge into db
            self.dbstore.cahandler_add(data_dic)

    def _challenge_info(self, authzr: messages.AuthorizationResource, user_key: josepy.jwk.JWKRSA):
        """ filter challenges and get challenge details """
        self.logger.debug('CAhandler._challenge_info()')

        chall_name = None
        chall_content = None

        if authzr and user_key:
            challenge = self._challenge_filter(authzr)
            if challenge:
                chall_content = challenge.chall.validation(user_key)
                try:
                    (chall_name, _token) = chall_content.split('.', 2)
                except Exception:
                    self.logger.error('CAhandler._challenge_info() challenge split failed: %s', chall_content)

            else:
                challenge = self._challenge_filter(authzr, chall_type='sectigo-email-01')
                chall_content = challenge.to_partial_json()

        else:
            if authzr:
                self.logger.error('CAhandler._challenge_info() userkey is missing')
            else:
                self.logger.error('CAhandler._challenge_info() authzr is missing')
            challenge = None

        self.logger.debug('CAhandler._challenge_info() ended with %s', chall_name)
        return (chall_name, chall_content, challenge)

    def _key_generate(self) -> josepy.jwk.JWKRSA:
        """ generate key """
        self.logger.debug('CAhandler._key_generate(%s)', self.key_size)
        user_key = josepy.JWKRSA(
            key=rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_size,
                backend=default_backend()
            )
        )
        self.logger.debug('CAhandler._key_generate() ended.')
        return user_key

    def _user_key_load(self) -> josepy.jwk.JWKRSA:
        """ enroll certificate  """
        self.logger.debug('CAhandler._user_key_load(%s)', self.keyfile)

        if os.path.exists(self.keyfile):
            self.logger.debug('CAhandler.enroll() opening user_key')
            with open(self.keyfile, "r", encoding='utf8') as keyf:
                user_key = josepy.JWKRSA.json_loads(keyf.read())
        else:
            self.logger.debug('CAhandler.enroll() generate and register key')
            user_key = self._key_generate()
            # dump keyfile to file
            try:
                with open(self.keyfile, "w", encoding='utf8') as keyf:
                    keyf.write(json.dumps(user_key.to_json()))
            except Exception as err:
                self.logger.error('Error during key dumping: %s', err)

        self.logger.debug('CAhandler._user_key_load() ended with: %s', bool(user_key))
        return user_key

    def _order_authorization(self, acmeclient: client.ClientV2, order: messages.OrderResource, user_key: josepy.jwk.JWKRSA) -> bool:
        """ validate challgenges """
        self.logger.debug('CAhandler._order_authorization()')

        authz_valid = False

        # query challenges
        for authzr in list(order.authorizations):
            (challenge_name, challenge_content, challenge) = self._challenge_info(authzr, user_key)
            if challenge_name and challenge_content:
                self.logger.debug('CAhandler._order_authorization(): http-01 challenge detected')
                # store challenge in database to allow challenge validation
                self._challenge_store(challenge_name, challenge_content)
                _auth_response = acmeclient.answer_challenge(challenge, challenge.chall.response(user_key))  # lgtm [py/unused-local-variable]
                authz_valid = True
            else:
                if isinstance(challenge_content, dict):
                    if 'type' in challenge_content and challenge_content['type'] == 'sectigo-email-01' and 'status' in challenge_content and challenge_content['status'] == 'valid':
                        self.logger.debug('CAhandler._order_authorization(): sectigo-email-01 challenge detected')
                        authz_valid = True

        self.logger.debug('CAhandler._order_authorization() ended with: %s', authz_valid)
        return authz_valid

    def _order_issue(self, acmeclient: client.ClientV2, user_key: josepy.jwk.JWKRSA, csr_pem: str) -> Tuple[str, str, str]:
        """ isuse order """
        self.logger.debug('CAhandler.enroll() issuing signing order')
        self.logger.debug('CAhandler.enroll() csr: ' + str(csr_pem))
        order = acmeclient.new_order(csr_pem)

        error = None
        cert_bundle = None
        cert_raw = None

        # valid orders
        order_valid = self._order_authorization(acmeclient, order, user_key)

        if order_valid:
            self.logger.debug('CAhandler.enroll() polling for certificate')
            order = acmeclient.poll_and_finalize(order)

            if order.fullchain_pem:
                self.logger.debug('CAhandler.enroll() successful')
                cert_bundle = str(order.fullchain_pem)
                cert_raw = str(base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_ASN1, crypto.load_certificate(crypto.FILETYPE_PEM, cert_bundle))), 'utf-8')
            else:
                self.logger.error('CAhandler.enroll: Error getting certificate: %s', order.error)
                error = f'Error getting certificate: {order.error}'

        self.logger.debug('CAhandler.enroll() ended')
        return (error, cert_bundle, cert_raw)

    def _account_lookup(self, acmeclient: client.ClientV2, reg: str, directory: messages.Directory):
        """ lookup account """
        self.logger.debug('CAhandler._account_lookup()')

        response = acmeclient._post(directory['newAccount'], reg)
        regr = acmeclient._regr_from_response(response)
        regr = acmeclient.query_registration(regr)
        if regr:
            self.logger.info('CAhandler._account_lookup: found existing account: %s', regr.uri)
            self.account = regr.uri
            if self.url:
                # remove url from string
                self.account = self.account.replace(self.url, '')
            if 'acct_path' in self.path_dic and self.path_dic['acct_path']:
                # remove acc_path
                self.account = self.account.replace(self.path_dic['acct_path'], '')

    def _account_create(self, acmeclient: client.ClientV2, user_key: josepy.jwk.JWKRSA, directory: messages.Directory) -> messages.RegistrationResource:
        """ register account """
        self.logger.debug('CAhandler._account_create(): register new account with email: %s', self.email)

        regr = None
        if self.email:
            self.logger.debug('CAhandler.__account_register(): register new account with email: %s', self.email)
            if self.url and 'host' in self.url_dic and self.url_dic['host'].endswith('zerossl.com'):  # lgtm [py/incomplete-url-substring-sanitization]
                # get zerossl eab credentials
                self._zerossl_eab_get()
            if self.eab_kid and self.eab_hmac_key:
                # we have to do some freaky eab to keep ZeroSSL happy
                eab = messages.ExternalAccountBinding.from_data(account_public_key=user_key, kid=self.eab_kid, hmac_key=self.eab_hmac_key, directory=directory)
                reg = messages.NewRegistration.from_data(key=user_key, email=self.email, terms_of_service_agreed=True, external_account_binding=eab)
            else:
                # register with email
                reg = messages.NewRegistration.from_data(key=user_key, email=self.email, terms_of_service_agreed=True)
            regr = acmeclient.new_account(reg)
            self.logger.debug('CAhandler.__account_register(): new account reqistered: %s', regr.uri)
        else:
            self.logger.error('CAhandler.__account_register(): registration aborted. Email address is missing')
            regr = None

        self.logger.debug('CAhandler._account_create() ended with: %s', bool(regr))
        return regr

    def _account_register(self, acmeclient: client.ClientV2, user_key: josepy.jwk.JWKRSA, directory: messages.Directory) -> messages.RegistrationResource:
        """ register account / check registration """
        self.logger.debug('CAhandler._account_register(%s)', self.email)
        try:
            # we assume that the account exist and need to query the account id
            reg = messages.NewRegistration.from_data(key=user_key, email=self.email, terms_of_service_agreed=True, only_return_existing=True)
            response = acmeclient._post(directory['newAccount'], reg)
            regr = acmeclient._regr_from_response(response)
            regr = acmeclient.query_registration(regr)
            self.logger.debug('CAhandler.__account_register(): found existing account: %s', regr.uri)
        except Exception:
            regr = self._account_create(acmeclient, user_key, directory)

        if regr:
            if self.url and 'acct_path' in self.path_dic:
                self.account = regr.uri.replace(self.url, '').replace(self.path_dic['acct_path'], '')
            if self.account:
                self.logger.info('acme-account id is %s. Please add an corresponding acme_account parameter to your acme_srv.cfg to avoid unnecessary lookups', self.account)

        return regr

    def _zerossl_eab_get(self):
        """ get eab credentials from zerossl """
        self.logger.debug('CAhandler._zerossl_eab_get()')

        zero_eab_email = "http://api.zerossl.com/acme/eab-credentials-email"
        data = {'email': self.email}

        response = requests.post(zero_eab_email, data=data, timeout=20)
        if 'success' in response.json() and response.json()['success'] and 'eab_kid' in response.json() and 'eab_hmac_key' in response.json():
            self.eab_kid = response.json()['eab_kid']
            self.eab_hmac_key = response.json()['eab_hmac_key']
            self.logger.debug('CAhandler._zerossl_eab_get() ended successfully')
        else:
            self.logger.error('CAhandler._zerossl_eab_get() failed: %s', response.text)

    def _eab_profile_string_check(self, key, value):
        self.logger.debug('CAhandler._eab_profile_string_check(): string: key: %s, value: %s', key, value)

        if hasattr(self, key):
            self.logger.debug('CAhandler._eab_profile_string_check(): setting attribute: %s to %s', key, value)
            setattr(self, key, value)
        else:
            self.logger.error('CAhandler._eab_profile_string_check(): ignore string attribute: key: %s value: %s', key, value)

        self.logger.debug('CAhandler._eab_profile_string_check() ended')

    def _eab_profile_list_check(self, eab_handler, csr, key, value):
        self.logger.debug('CAhandler._eab_profile_list_check(): list: key: %s, value: %s', key, value)

        result = None
        if hasattr(self, key) and key != 'allowed_domainlist':
            new_value, error = header_info_field_validate(self.logger, csr, self.header_info_field, key, value)
            if new_value:
                self.logger.debug('CAhandler._eab_profile_list_check(): setting attribute: %s to %s', key, new_value)
                setattr(self, key, new_value)
            else:
                result = error
        elif key == 'allowed_domainlist':
            # check if csr contains allowed domains
            error = eab_handler.allowed_domains_check(csr, value)
            if error:
                result = error
        else:
            self.logger.error('CAhandler._eab_profile_list_check(): ignore list attribute: key: %s value: %s', key, value)

        self.logger.debug('CAhandler._eab_profile_list_check() ended with: %s', result)
        return result

    def _eab_profile_check(self, csr: str, handler_hifield: str) -> str:
        """ check eab profile"""
        self.logger.debug('CAhandler._eab_profile_check()')

        result = None
        with self.eab_handler(self.logger) as eab_handler:
            eab_profile_dic = eab_handler.eab_profile_get(csr)
            for key, value in eab_profile_dic.items():
                if isinstance(value, str):
                    self._eab_profile_string_check(key, value)
                elif isinstance(value, list):
                    result = self._eab_profile_list_check(eab_handler, csr, key, value)
                    if result:
                        break

            # we need to reject situations where profiling is enabled but the header_hifiled is not defined in json
            if self.header_info_field and handler_hifield not in eab_profile_dic:
                hil_value = header_info_lookup(self.logger, csr, self.header_info_field, handler_hifield)
                if hil_value:
                    # setattr(self, handler_hifield, hil_value)
                    result = f'header_info field "{handler_hifield}" is not allowed by profile'

        self.logger.debug('CAhandler._eab_profile_check() ended with: %s', result)
        return result

    def _profile_check(self, csr: str) -> str:
        """ check profile """
        self.logger.debug('CAhandler._profile_check()')
        error = None

        # handler specific header info field
        handler_hifield = "acme_url"

        if self.eab_profiling:
            if self.eab_handler:
                error = self._eab_profile_check(csr, handler_hifield)
                # we need to cover cases where handler_value is enabled but nothing is defined in json
            else:
                self.logger.error('CAhandler._profile_check(): eab_profiling enabled but no handler defined')
        elif self.header_info_field:
            # no profiling - parse profileid from http_header
            hil_value = header_info_lookup(self.logger, csr, self.header_info_field, handler_hifield)
            if hil_value:
                self.logger.debug('CAhandler._profile_check(): setting %s to %s', handler_hifield, hil_value)
                setattr(self, handler_hifield, hil_value)

        self.logger.debug('CAhandler._profile_check() ended with %s', error)
        return error

    def enroll(self, csr: str) -> Tuple[str, str, str, str]:
        """ enroll certificate  """
        # pylint: disable=R0915
        self.logger.debug('CAhandler.enroll()')

        csr_pem = f'-----BEGIN CERTIFICATE REQUEST-----\n{textwrap.fill(str(b64_url_recode(self.logger, csr)), 64)}\n-----END CERTIFICATE REQUEST-----\n'

        cert_bundle = None
        error = None
        cert_raw = None
        poll_indentifier = None
        user_key = None

        # check CN and SAN against black/whitlist
        if self.allowed_domainlist:
            # check sans / cn against list of allowed comains from config
            result = allowed_domainlist_check(self.logger, csr, self.allowed_domainlist)
        else:
            result = True

        # check for eab profiling and header_info
        error = self._profile_check(csr)

        if result and not error:
            try:
                user_key = self._user_key_load()
                net = client.ClientNetwork(user_key)

                directory = messages.Directory.from_json(net.get(f'{self.url}{self.path_dic["directory_path"]}').json())
                acmeclient = client.ClientV2(directory, net=net)
                reg = messages.Registration.from_data(key=user_key, terms_of_service_agreed=True)

                if self.account:
                    regr = messages.RegistrationResource(uri=f"{self.url}{self.path_dic['acct_path']}{self.account}", body=reg)
                    self.logger.debug('CAhandler.enroll(): checking remote registration status')
                    regr = acmeclient.query_registration(regr)
                else:
                    # new account or existing account with missing account id
                    regr = self._account_register(acmeclient, user_key, directory)

                if regr.body.status == "valid":
                    (error, cert_bundle, cert_raw) = self._order_issue(acmeclient, user_key, csr_pem)
                elif not regr.body.status and regr.uri:
                    # this is an exisitng but not configured account. Throw error but continue enrolling
                    self.logger.info('Existing but not configured ACME account: %s', regr.uri)
                    (error, cert_bundle, cert_raw) = self._order_issue(acmeclient, user_key, csr_pem)
                else:
                    self.logger.error('CAhandler.enroll: Bad ACME account: %s', regr.body.error)
                    error = f'Bad ACME account: {regr.body.error}'
            except Exception as err:
                self.logger.error('CAhandler.enroll: error: %s', err)
                error = str(err)
            finally:
                del user_key

        else:
            error = 'CSR rejected. Either CN or SANs are not allowed by policy'
            self.logger.error('CAhandler.enroll: CSR rejected. Either CN or SANs are not allowed by policy.')

        self.logger.debug('Certificate.enroll() ended')
        return (error, cert_bundle, cert_raw, poll_indentifier)

    def poll(self, _cert_name: str, poll_identifier: str, _csr: str) -> Tuple[str, str, str, str, bool]:
        """ poll status of pending CSR and download certificates """
        self.logger.debug('CAhandler.poll()')

        error = "Not implemented"
        cert_bundle = None
        cert_raw = None
        rejected = False

        self.logger.debug('CAhandler.poll() ended')
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(self, _cert: str, _rev_reason: str, _rev_date: str) -> Tuple[int, str, str]:
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke()')

        user_key = None
        code = 500
        message = 'urn:ietf:params:acme:error:serverInternal'
        detail = None

        try:
            certpem = f'-----BEGIN CERTIFICATE-----\n{textwrap.fill(str(b64_url_recode(self.logger, _cert)), 64)}\n-----END CERTIFICATE-----\n'
            cert = josepy.ComparableX509(crypto.load_certificate(crypto.FILETYPE_PEM, certpem))

            if os.path.exists(self.keyfile):
                user_key = self._user_key_load()
            net = client.ClientNetwork(user_key)

            if user_key:
                directory = messages.Directory.from_json(net.get(f"{self.url}{self.path_dic['directory_path']}").json())
                acmeclient = client.ClientV2(directory, net=net)
                reg = messages.NewRegistration.from_data(key=user_key, email=self.email, terms_of_service_agreed=True, only_return_existing=True)

                if not self.account:
                    self._account_lookup(acmeclient, reg, directory)

                if self.account:
                    regr = messages.RegistrationResource(uri=f"{self.url}{self.path_dic['acct_path']}{self.account}", body=reg)
                    self.logger.debug('CAhandler.revoke() checking remote registration status')
                    regr = acmeclient.query_registration(regr)

                    if regr.body.status == "valid":
                        self.logger.debug('CAhandler.revoke() issuing revocation order')
                        acmeclient.revoke(cert, 1)
                        self.logger.debug('CAhandler.revoke() successfull')
                        code = 200
                        message = None
                    else:
                        self.logger.error('CAhandler.enroll: Bad ACME account: %s', regr.body.error)
                        detail = f'Bad ACME account: {regr.body.error}'

                else:
                    self.logger.error('CAhandler.revoke(): could not find account key and lookup at acme-endpoint failed.')
                    detail = 'account lookup failed'
            else:
                self.logger.error('CAhandler.revoke(): could not load user_key %s', self.keyfile)
                detail = 'Internal Error'

        except Exception as err:
            self.logger.error('CAhandler.enroll: error: %s', err)
            detail = str(err)

        finally:
            del user_key

        self.logger.debug('Certificate.revoke() ended')
        return (code, message, detail)

    def trigger(self, _payload: str) -> Tuple[int, str, str]:
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')

        error = "Not implemented"
        cert_bundle = None
        cert_raw = None

        self.logger.debug('CAhandler.trigger() ended with error: %s', error)
        return (error, cert_bundle, cert_raw)
