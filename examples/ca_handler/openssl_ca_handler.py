#!/usr/bin/python
# -*- coding: utf-8 -*-
""" handler for an openssl ca """
from __future__ import print_function
import os
import json
import base64
import uuid
import re
from OpenSSL import crypto
# pylint: disable=C0209, E0401, R0913
from acme_srv.helper import load_config, build_pem_file, uts_now, uts_to_date_utc, b64_url_recode, cert_serial_get, convert_string_to_byte, convert_byte_to_string, csr_cn_get, csr_san_get


class CAhandler(object):
    """ CA  handler """

    def __init__(self, debug=None, logger=None):
        self.debug = debug
        self.logger = logger
        self.issuer_dict = {
            'issuing_ca_key': None,
            'issuing_ca_cert': None,
            'issuing_ca_crl': None,
        }
        self.ca_cert_chain_list = []
        self.cert_validity_days = 365
        self.openssl_conf = None
        self.cert_save_path = None
        self.save_cert_as_hex = False
        self.allowed_domainlist = []
        self.blocked_domainlist = []
        self.cn_enforce = False

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        if not self.issuer_dict['issuing_ca_key']:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _ca_load(self):
        """ load ca key and cert """
        self.logger.debug('CAhandler._ca_load()')
        ca_key = None
        ca_cert = None
        # open key and cert
        if 'issuing_ca_key' in self.issuer_dict:
            if os.path.exists(self.issuer_dict['issuing_ca_key']):
                if 'passphrase' in self.issuer_dict:
                    with open(self.issuer_dict['issuing_ca_key'], 'r', encoding='utf8') as fso:
                        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, fso.read(), convert_string_to_byte(self.issuer_dict['passphrase']))
                else:
                    with open(self.issuer_dict['issuing_ca_key'], 'r', encoding='utf8') as fso:
                        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, fso.read())
        if 'issuing_ca_cert' in self.issuer_dict:
            if os.path.exists(self.issuer_dict['issuing_ca_cert']):
                with open(self.issuer_dict['issuing_ca_cert'], 'r', encoding='utf8') as fso:
                    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, fso.read())
        self.logger.debug('CAhandler._ca_load() ended')
        return (ca_key, ca_cert)

    def _chain_verify(self, cert, ca_cert, error):
        """ Create a certificate store and add ca cert(s) """
        self.logger.debug('CAhandler._certificate_chain_verify()')

        try:
            store = crypto.X509Store()
            store.add_cert(ca_cert)
        except Exception:
            error = 'issuing certificate could not be added to trust-store'

        if not error:
            # add ca chain to truststore
            for cert_name in self.ca_cert_chain_list:
                try:
                    with open(cert_name, 'r', encoding='utf8') as fso:
                        cain_cert = crypto.load_certificate(crypto.FILETYPE_PEM, fso.read())
                    store.add_cert(cain_cert)
                except Exception:
                    error = 'certificate {0} could not be added to trust store'.format(cert_name)

        if not error:
            # Create a certificate context using the store and the downloaded certificate
            store_ctx = crypto.X509StoreContext(store, cert)
            # Verify the certificate, returns None if it can validate the certificate
            try:
                # pylint: disable=E1111
                result = store_ctx.verify_certificate()
            except Exception as err_:
                result = str(err_)
        else:
            result = error

        return result

    def _certificate_chain_verify(self, cert, ca_cert):
        """ verify certificate chain """
        self.logger.debug('CAhandler._certificate_chain_verify()')

        error = None
        pem_file = build_pem_file(self.logger, None, b64_url_recode(self.logger, cert), True)

        try:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_file)
        except Exception as err_:
            cert = None
            error = err_

        if not error:
            result = self._chain_verify(cert, ca_cert, error)
        else:
            result = 'certificate could not get parsed'

        self.logger.debug('CAhandler._certificate_chain_verify() ended with {0}'.format(result))
        return result

    def _certificate_extensions_add(self, cert_extension_dic, cert, ca_cert):
        """ verify certificate chain """
        self.logger.debug('CAhandler._certificate_extensions_add()')

        _tmp_list = []
        # add extensins from config file
        for extension in cert_extension_dic:
            self.logger.debug('adding extension: {0}: {1}: {2}'.format(extension, cert_extension_dic[extension]['critical'], cert_extension_dic[extension]['value']))
            if extension == 'subjectKeyIdentifier':
                self.logger.info('_certificate_extensions_add(): subjectKeyIdentifier')
                _tmp_list.append(crypto.X509Extension(convert_string_to_byte(extension), critical=cert_extension_dic[extension]['critical'], value=convert_string_to_byte(cert_extension_dic[extension]['value']), subject=cert))
            elif 'subject' in cert_extension_dic[extension]:
                self.logger.info('_certificate_extensions_add(): subject')
                _tmp_list.append(crypto.X509Extension(convert_string_to_byte(extension), critical=cert_extension_dic[extension]['critical'], value=convert_string_to_byte(cert_extension_dic[extension]['value']), subject=cert))
            elif 'issuer' in cert_extension_dic[extension]:
                self.logger.info('_certificate_extensions_add(): issuer')
                _tmp_list.append(crypto.X509Extension(convert_string_to_byte(extension), critical=cert_extension_dic[extension]['critical'], value=convert_string_to_byte(cert_extension_dic[extension]['value']), issuer=ca_cert))
            else:
                _tmp_list.append(crypto.X509Extension(type_name=convert_string_to_byte(extension), critical=cert_extension_dic[extension]['critical'], value=convert_string_to_byte(cert_extension_dic[extension]['value'])))

        self.logger.debug('CAhandler._certificate_extensions_add() ended')
        return _tmp_list

    def _certificate_extensions_load(self):
        """ verify certificate chain """
        self.logger.debug('CAhandler._certificate_extensions_load()')

        file_dic = dict(load_config(self.logger, None, self.openssl_conf))

        cert_extention_dic = {}
        if 'extensions' in file_dic:
            for extension in file_dic['extensions']:

                cert_extention_dic[extension] = {}
                parameters = file_dic['extensions'][extension].split(',')

                # set crititcal task if applicable
                if parameters[0] == 'critical':
                    cert_extention_dic[extension]['critical'] = bool(parameters.pop(0))
                else:
                    cert_extention_dic[extension]['critical'] = False

                # remove leading blank from first element
                parameters[0] = parameters[0].lstrip()

                # check if we have an issuer option (if so remove it and mark it as to be set)
                if 'issuer:' in parameters[-1]:
                    cert_extention_dic[extension]['issuer'] = bool(parameters.pop(-1))

                # check if we have an issuer option (if so remove it and mark it as to be set)
                if 'subject:' in parameters[-1]:
                    cert_extention_dic[extension]['subject'] = bool(parameters.pop(-1))

                # combine the remaining items and put them in as values
                cert_extention_dic[extension]['value'] = ','.join(parameters)

        self.logger.debug('CAhandler._certificate_extensions_load() ended')
        return cert_extention_dic

    def _certificate_store(self, cert):
        """ store certificate on disk """
        self.logger.debug('CAhandler._certificate_store()')
        serial = cert.get_serial_number()
        # save cert if needed
        if self.cert_save_path and self.cert_save_path is not None:
            # create cert-store dir if not existing
            if not os.path.isdir(self.cert_save_path):
                self.logger.debug('create certsavedir {0}'.format(self.cert_save_path))
                os.mkdir(self.cert_save_path)

            # determine filename
            if self.save_cert_as_hex:
                self.logger.info('convert serial to hex: {0}: {1}'.format(serial, '{:X}'.format(serial)))
                cert_file = '{:X}'.format(serial)
            else:
                cert_file = str(serial)
            with open('{0}/{1}.pem'.format(self.cert_save_path, cert_file), 'wb') as fso:
                fso.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        else:
            self.logger.error('CAhandler._certificate_store() handler configuration incomplete: cert_save_path is missing')

        self.logger.debug('CAhandler._certificate_store() ended')

    def _config_check_issuer(self):
        """ check issuing CA configuration """
        self.logger.debug('CAhandler._config_check_issuer()')

        error = None
        if 'issuing_ca_key' in self.issuer_dict and self.issuer_dict['issuing_ca_key']:
            if not os.path.exists(self.issuer_dict['issuing_ca_key']):
                error = 'issuing_ca_key {0} does not exist'.format(self.issuer_dict['issuing_ca_key'])
        else:
            error = 'issuing_ca_key not specfied in config_file'

        if not error:
            if 'issuing_ca_cert' in self.issuer_dict and self.issuer_dict['issuing_ca_cert']:
                if not os.path.exists(self.issuer_dict['issuing_ca_cert']):
                    error = 'issuing_ca_cert {0} does not exist'.format(self.issuer_dict['issuing_ca_cert'])
            else:
                error = 'issuing_ca_cert must be specified in config file'

        self.logger.debug('CAhandler._config_check_issuer() ended with:  {0}'.format(error))
        return error

    def _config_check_crl(self, error):
        """ check crl config """
        self.logger.debug('CAhandler._config_check_crl()')

        if not error:
            if 'issuing_ca_crl' in self.issuer_dict and self.issuer_dict['issuing_ca_crl']:
                if not os.path.exists(self.issuer_dict['issuing_ca_crl']):
                    error = 'issuing_ca_crl {0} does not exist'.format(self.issuer_dict['issuing_ca_crl'])
            else:
                error = 'issuing_ca_crl must be specified in config file'

        self.logger.debug('CAhandler._config_check_crl() ended with:  {0}'.format(error))
        return error

    def _config_parameters_check(self, error):
        """ check remaining configuration """
        self.logger.debug('CAhandler._config_parameters_check()')

        if not error:
            if self.cert_save_path:
                if not os.path.exists(self.cert_save_path):
                    error = 'cert_save_path {0} does not exist'.format(self.cert_save_path)
            else:
                error = 'cert_save_path must be specified in config file'

        if not error and self.openssl_conf and not os.path.exists(self.openssl_conf):
            error = 'openssl_conf {0} does not exist'.format(self.openssl_conf)

        if not error and not self.ca_cert_chain_list:
            error = 'ca_cert_chain_list must be specified in config file'

        self.logger.debug('CAhandler._config_parameters_check() ended with:  {0}'.format(error))
        return error

    def _config_check(self):
        """ check config for consitency """
        self.logger.debug('CAhandler._config_check()')

        # run checks
        error = self._config_check_issuer()
        error = self._config_check_crl(error)
        error = self._config_parameters_check(error)

        if error:
            self.logger.error('CAhandler config error: {0}'.format(error))

        self.logger.debug('CAhandler._config_check() ended')
        return error

    def _config_domainlists_load(self, config_dic):
        """" load config from file """
        self.logger.debug('CAhandler._config_domainlists_load()')
        if 'openssl_conf' in config_dic['CAhandler']:
            self.openssl_conf = config_dic['CAhandler']['openssl_conf']
        if 'allowed_domainlist' in config_dic['CAhandler']:
            self.allowed_domainlist = json.loads(config_dic['CAhandler']['allowed_domainlist'])
        if 'blocked_domainlist' in config_dic['CAhandler']:
            self.blocked_domainlist = json.loads(config_dic['CAhandler']['blocked_domainlist'])
        if 'whitelist' in config_dic['CAhandler']:
            self.allowed_domainlist = json.loads(config_dic['CAhandler']['whitelist'])
            self.logger.error('CAhandler._config_load() found "whitelist" parameter in configfile which should be renamed to "allowed_domainlist"')
        if 'blacklist' in config_dic['CAhandler']:
            self.blocked_domainlist = json.loads(config_dic['CAhandler']['blacklist'])
            self.logger.error('CAhandler._config_load() found "blacklist" parameter in configfile which should be renamed to "blocked_domainlist"')
        self.logger.debug('CAhandler._config_domainlists_load() ended')

    def _config_credentials_load(self, config_dic):
        """ load credential config """
        self.logger.debug('CAhandler._config_credentials_load()')

        if 'issuing_ca_key' in config_dic['CAhandler']:
            self.issuer_dict['issuing_ca_key'] = config_dic['CAhandler']['issuing_ca_key']
        if 'issuing_ca_cert' in config_dic['CAhandler']:
            self.issuer_dict['issuing_ca_cert'] = config_dic['CAhandler']['issuing_ca_cert']
        if 'issuing_ca_key_passphrase_variable' in config_dic['CAhandler']:
            try:
                self.issuer_dict['passphrase'] = os.environ[config_dic['CAhandler']['issuing_ca_key_passphrase_variable']]
            except Exception as err:
                self.logger.error('CAhandler._config_load() could not load issuing_ca_key_passphrase_variable:{0}'.format(err))
        if 'issuing_ca_key_passphrase' in config_dic['CAhandler']:
            if 'passphrase' in self.issuer_dict and self.issuer_dict['passphrase']:
                self.logger.info('CAhandler._config_load() overwrite issuing_ca_key_passphrase_variable')
            self.issuer_dict['passphrase'] = config_dic['CAhandler']['issuing_ca_key_passphrase']

        # convert passphrase
        if 'passphrase' in self.issuer_dict:
            self.issuer_dict['passphrase'] = self.issuer_dict['passphrase'].encode('ascii')

        self.logger.debug('CAhandler._config_credentials_load() ended')

    def _config_policy_load(self, config_dic):
        """ load certificate policy """
        self.logger.debug('CAhandler._config_policy_load()')

        if 'ca_cert_chain_list' in config_dic['CAhandler']:
            self.ca_cert_chain_list = json.loads(config_dic['CAhandler']['ca_cert_chain_list'])
        if 'cert_validity_days' in config_dic['CAhandler']:
            self.cert_validity_days = int(config_dic['CAhandler']['cert_validity_days'])
        if 'cert_save_path' in config_dic['CAhandler']:
            self.cert_save_path = config_dic['CAhandler']['cert_save_path']
        if 'issuing_ca_crl' in config_dic['CAhandler']:
            self.issuer_dict['issuing_ca_crl'] = config_dic['CAhandler']['issuing_ca_crl']
        try:
            self.cn_enforce = config_dic.getboolean('CAhandler', 'cn_enforce', fallback=False)
        except Exception:
            self.logger.error('CAhandler._config_load() variable cn_enforce cannot be parsed')

        self.logger.debug('CAhandler._config_policy_load() ended')

    def _config_load(self):
        """" load config from file """
        self.logger.debug('CAhandler._config_load()')
        config_dic = load_config(self.logger, 'CAhandler')

        # load credentials
        self._config_credentials_load(config_dic)

        # load policy options
        self._config_policy_load(config_dic)

        # load allow/block lists
        self._config_domainlists_load(config_dic)

        self.save_cert_as_hex = config_dic.getboolean('CAhandler', 'save_cert_as_hex', fallback=False)
        self.logger.debug('CAhandler._config_load() ended')

    def _crl_check(self, crl, serial):
        """ check if CRL already contains serial """
        self.logger.debug('CAhandler._crl_check()')
        sn_match = False

        # convert to lower case
        if isinstance(serial, str):
            serial = serial.lower()

        serial = convert_string_to_byte(serial)
        if crl and serial:
            crl_list = crl.get_revoked()
            if crl_list:
                for rev in crl_list:
                    if serial == rev.get_serial().lower():
                        sn_match = True
                        break
        self.logger.debug('CAhandler._crl_check() with:{0}'.format(sn_match))
        return sn_match

    def _chk_san_lists_get(self, csr):
        """ check lists  """
        self.logger.debug('CAhandler._chk_san_lists_get()')

        # get sans and build a list
        _san_list = csr_san_get(self.logger, csr)

        check_list = []
        san_list = []

        if _san_list:
            for san in _san_list:
                try:
                    # SAN list must be modified/filtered)
                    (_san_type, san_value) = san.lower().split(':')
                    san_list.append(san_value)
                except Exception:
                    # force check to fail as something went wrong during parsing
                    check_list.append(False)
                    self.logger.debug('CAhandler._csr_check(): san_list parsing failed at entry: {0}'.format(san))

        self.logger.debug('CAhandler._chk_san_lists_get() ended')
        return (san_list, check_list)

    def _cn_add(self, csr, san_list):
        """ add CN if required """
        self.logger.debug('CAhandler._cn_add()')

        # get common name and attach it to san_list
        cn_ = csr_cn_get(self.logger, csr)

        if not cn_ and san_list:
            enforced_cn = san_list[0]
            self.logger.info('CAhandler._csr_check(): enforce CN to {0}'.format(enforced_cn))
        else:
            enforced_cn = None

        if cn_:
            cn_ = cn_.lower()
            if cn_ not in san_list:
                # append cn to san_list
                self.logger.debug('Ahandler._csr_check(): append cn to san_list')
                san_list.append(cn_)

        self.logger.debug('CAhandler._cn_add() ended with: {0}'.format(enforced_cn))
        return (san_list, enforced_cn)

    def _csr_check(self, csr):
        """ check CSR against definied allowed_domainlists """
        self.logger.debug('CAhandler._csr_check()')

        (san_list, check_list) = self._chk_san_lists_get(csr)
        (san_list, enforced_cn) = self._cn_add(csr, san_list)

        if self.allowed_domainlist or self.blocked_domainlist:
            result = False

            # go over the san list and check each entry
            for san in san_list:
                check_list.append(self._string_wlbl_check(san, self.allowed_domainlist, self.blocked_domainlist))

            if check_list:
                # cover a cornercase with empty checklist (no san, no cn)
                if False in check_list:
                    result = False
                else:
                    result = True
        else:
            result = True

        self.logger.debug('CAhandler._csr_check() ended with: {0} enforce_cn: {1}'.format(result, enforced_cn))
        return (result, enforced_cn)

    def _list_regex_check(self, entry, list_):
        """ check entry against regex """
        self.logger.debug('CAhandler._list_regex_check()')

        check_result = False
        for regex in list_:
            if regex.startswith('*.'):
                regex = regex.replace('*.', '.')
            regex_compiled = re.compile(regex)
            if bool(regex_compiled.search(entry)):
                # parameter is in set flag accordingly and stop loop
                check_result = True

        self.logger.debug('CAhandler._list_regex_check() ended with: {0}'.format(check_result))
        return check_result

    def _list_check(self, entry, list_, toggle=False):
        """ check string against list """
        self.logger.debug('CAhandler._list_check({0}:{1})'.format(entry, toggle))
        self.logger.debug('check against list: {0}'.format(list_))

        # default setting
        check_result = False

        if entry:
            if list_:
                check_result = self._list_regex_check(entry, list_)
            else:
                # empty list, flip parameter to make the check successful
                check_result = True

        if toggle:
            # toggle result if this is a blocked_domainlist
            check_result = not check_result

        self.logger.debug('CAhandler._list_check() ended with: {0}'.format(check_result))
        return check_result

    def _pemcertchain_generate(self, ee_cert, issuer_cert):
        """ build pem chain """
        self.logger.debug('CAhandler._pemcertchain_generate()')

        if issuer_cert:
            pem_chain = '{0}{1}'.format(ee_cert, issuer_cert)
        else:
            pem_chain = ee_cert
        for cert in self.ca_cert_chain_list:
            if os.path.exists(cert):
                with open(cert, 'r', encoding='utf8') as fso:
                    cert_pem = fso.read()
                pem_chain = '{0}{1}'.format(pem_chain, cert_pem)

        self.logger.debug('CAhandler._pemcertchain_generate() ended')
        return pem_chain

    def _string_wlbl_check(self, entry, white_list, black_list):
        """ check single against allowed_domainlist and blocked_domainlist """
        self.logger.debug('CAhandler._string_wlbl_check({0})'.format(entry))

        # default setting
        chk_result = False

        # check if entry is in white_list
        wl_check = self._list_check(entry, white_list)
        if wl_check:
            self.logger.debug('{0} in white_list'.format(entry))
            if black_list:
                # we need to check blocked_domainlist if there is a blocked_domainlist and wl check passed
                if self._list_check(entry, black_list):
                    self.logger.debug('{0} in black_list'.format(entry))
                else:
                    self.logger.debug('{0} not in black_list'.format(entry))
                    chk_result = True
            else:
                chk_result = wl_check
        else:
            self.logger.debug('{0} not in white_list'.format(entry))

        self.logger.debug('CAhandler._string_wlbl_check({0}) ended with: {1}'.format(entry, chk_result))
        return chk_result

    def _duplicates_clean(self, default_extension_list, csr_extension_list):
        """ clean duplicate extensions """

        extension_list = []
        for csr_ext in csr_extension_list:
            ext_in = False
            csr_ext_name = csr_ext.get_short_name()

            for def_ext in default_extension_list:
                if csr_ext_name == def_ext.get_short_name():
                    ext_in = True
                    break

            if not ext_in:
                extension_list.append(csr_ext)

        for def_ext in default_extension_list:
            extension_list.append(def_ext)

        return extension_list

    def _cert_extension_dic_add(self, cert, ca_cert, cert_extension_dic, default_extension_list, req):
        """ add extension from templat """
        self.logger.debug('CAhandler._cert_extension_dic_add()')

        try:
            # remove duplicate extensions
            extension_list = self._duplicates_clean(default_extension_list, self._certificate_extensions_add(cert_extension_dic, cert, ca_cert))
        except Exception as err_:
            self.logger.error('CAhandler.enroll() error while loading extensions form file. Use default set.\nerror: {0}'.format(err_))
            # remove duplicate extensions
            extension_list = self._duplicates_clean(default_extension_list, req.get_extensions())

        return extension_list

    def _cert_extension_add(self, req, default_extension_list):
        """ add extensions """
        self.logger.debug('CAhandler._cert_extension_add()')

        # add keyUsage if it does not exist in CSR
        ku_is_in = False
        for ext in req.get_extensions():
            if convert_byte_to_string(ext.get_short_name()) == 'keyUsage':
                ku_is_in = True
        if not ku_is_in:
            default_extension_list.append(crypto.X509Extension(convert_string_to_byte('keyUsage'), True, convert_string_to_byte('digitalSignature,keyEncipherment')))

        # remove duplicate extensions
        extension_list = self._duplicates_clean(default_extension_list, req.get_extensions())

        self.logger.debug('CAhandler._cert_extension_add() ended')
        return extension_list

    def _cert_signing_prep(self, ca_cert, req, subject):
        """ enroll certificate """
        # pylint: disable=R0914, R0915
        self.logger.debug('CAhandler._cert_signing()')

        # sign csr
        cert = crypto.X509()
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(self.cert_validity_days * 86400)
        cert.set_issuer(ca_cert.get_subject())
        cert.set_subject(subject)
        cert.set_pubkey(req.get_pubkey())
        cert.set_serial_number(uuid.uuid4().int)
        cert.set_version(2)

        self.logger.debug('CAhandler._cert_signing() ended')
        return cert

    def _cert_extension_apply(self, cert, ca_cert, req):
        """ add cert extensions """
        self.logger.debug('CAhandler._cert_extension_apply()')

        default_extension_list = [
            crypto.X509Extension(convert_string_to_byte('subjectKeyIdentifier'), False, convert_string_to_byte('hash'), subject=cert),
            crypto.X509Extension(convert_string_to_byte('authorityKeyIdentifier'), False, convert_string_to_byte('keyid:always'), issuer=ca_cert),
            crypto.X509Extension(convert_string_to_byte('basicConstraints'), True, convert_string_to_byte('CA:FALSE')),
            crypto.X509Extension(convert_string_to_byte('extendedKeyUsage'), False, convert_string_to_byte('clientAuth,serverAuth')),
        ]

        # load certificate_profile (if applicable)
        if self.openssl_conf:
            cert_extension_dic = self._certificate_extensions_load()
        else:
            cert_extension_dic = []

        if cert_extension_dic:
            cert.add_extensions(self._cert_extension_dic_add(cert, ca_cert, cert_extension_dic, default_extension_list, req))
        else:
            cert.add_extensions(self._cert_extension_add(req, default_extension_list))

        self.logger.debug('CAhandler._cert_extension_apply() ended')
        return cert

    def enroll(self, csr):
        """ enroll certificate """
        # pylint: disable=R0914, R0915
        self.logger.debug('CAhandler.enroll()')

        cert_bundle = None
        cert_raw = None

        error = self._config_check()

        if not error:
            try:
                # check CN and SAN against black/whitlist
                (result, enforce_cn) = self._csr_check(csr)

                if result:
                    # prepare the CSR
                    csr = build_pem_file(self.logger, None, b64_url_recode(self.logger, csr), None, True)

                    # load ca cert and key
                    (ca_key, ca_cert) = self._ca_load()

                    # creating a rest form CSR
                    req = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)

                    subject = req.get_subject()
                    if self.cn_enforce and enforce_cn:
                        self.logger.info('CAhandler.enroll(): overwrite CN with {0}'.format(enforce_cn))
                        setattr(subject, 'CN', enforce_cn)

                    cert = self._cert_signing_prep(ca_cert, req, subject)
                    cert = self._cert_extension_apply(cert, ca_cert, req)

                    cert.sign(ca_key, 'sha256')

                    # store certifiate
                    self._certificate_store(cert)

                    # create bundle and raw cert
                    # pylint: disable=R1732
                    cert_bundle = self._pemcertchain_generate(convert_byte_to_string(crypto.dump_certificate(crypto.FILETYPE_PEM, cert)), open(self.issuer_dict['issuing_ca_cert'], encoding='utf8').read())
                    cert_raw = convert_byte_to_string(base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)))
                else:
                    error = 'urn:ietf:params:acme:badCSR'

            except Exception as err:
                self.logger.error('CAhandler.enroll() error: {0}'.format(err))
                error = 'Unknown exception'

        self.logger.debug('CAhandler.enroll() ended')
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

    def revoke(self, cert, rev_reason='unspecified', rev_date=None):
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke({0}: {1})'.format(rev_reason, rev_date))
        code = None
        message = None
        detail = None

        # overwrite revocation date - we ignore what has been submitted
        rev_date = uts_to_date_utc(uts_now(), '%y%m%d%H%M%SZ')

        if 'issuing_ca_crl' in self.issuer_dict and self.issuer_dict['issuing_ca_crl']:
            # load ca cert and key
            (ca_key, ca_cert) = self._ca_load()
            # turn of chain_check due to issues in pyopenssl (check is not working if key-usage is set)
            # result = self._certificate_chain_verify(cert, ca_cert)

            # proceed if the cert and ca-cert belong together
            serial = cert_serial_get(self.logger, cert)
            if ca_key and ca_cert and serial:
                serial = hex(serial).replace('0x', '')
                if os.path.exists(self.issuer_dict['issuing_ca_crl']):
                    # existing CRL
                    with open(self.issuer_dict['issuing_ca_crl'], 'r', encoding='utf8') as fso:
                        crl = crypto.load_crl(crypto.FILETYPE_PEM, fso.read())
                    # check CRL already contains serial
                    sn_match = self._crl_check(crl, serial)
                else:
                    # new CRL
                    crl = crypto.CRL()
                    sn_match = None

                # this is the revocation operation
                if not sn_match:
                    revoked = crypto.Revoked()
                    revoked.set_reason(convert_string_to_byte(rev_reason))
                    revoked.set_serial(convert_string_to_byte(serial))
                    revoked.set_rev_date(convert_string_to_byte(rev_date))
                    crl.add_revoked(revoked)
                    # save CRL
                    crl_text = crl.export(ca_cert, ca_key, crypto.FILETYPE_PEM, 7, convert_string_to_byte('sha256'))
                    with open(self.issuer_dict['issuing_ca_crl'], 'wb') as fso:
                        fso.write(crl_text)
                    code = 200
                else:
                    code = 400
                    message = 'urn:ietf:params:acme:error:alreadyRevoked'
                    detail = 'Certificate has already been revoked'
            else:
                code = 400
                message = 'urn:ietf:params:acme:error:serverInternal'
                detail = 'configuration error'
        else:
            code = 400
            message = 'urn:ietf:params:acme:error:serverInternal'
            detail = 'Unsupported operation'

        self.logger.debug('CAhandler.revoke() ended')
        return (code, message, detail)

    def trigger(self, _payload):
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')

        error = 'Method not implemented.'
        cert_bundle = None
        cert_raw = None

        self.logger.debug('CAhandler.trigger() ended with error: {0}'.format(error))
        return (error, cert_bundle, cert_raw)
