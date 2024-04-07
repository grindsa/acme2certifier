# -*- coding: utf-8 -*-
""" handler for xca ca handler """
from __future__ import print_function
import os
import sqlite3
import uuid
import json
import datetime
from typing import List, Tuple, Dict
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import BasicConstraints, ExtendedKeyUsage, SubjectKeyIdentifier, AuthorityKeyIdentifier, KeyUsage, SubjectAlternativeName
from cryptography.x509.oid import ExtendedKeyUsageOID
from OpenSSL import crypto as pyossslcrypto
# pylint: disable=e0401
from acme_srv.helper import load_config, build_pem_file, uts_now, uts_to_date_utc, b64_encode, b64_decode, b64_url_recode, cert_serial_get, convert_string_to_byte, convert_byte_to_string, csr_cn_get, csr_san_get, error_dic_get, header_info_lookup, header_info_field_validate, config_headerinfo_get, config_eab_profile_load


DEFAULT_DATE_FORMAT = '%Y%m%d%H%M%SZ'


def dict_from_row(row):
    """ small helper to convert the output of a "select" command into a dictionary """
    return dict(zip(row.keys(), row))


class CAhandler(object):
    """ CA  handler """

    def __init__(self, debug: bool = False, logger: object = None):
        self.debug = debug
        self.logger = logger
        self.xdb_file = None
        self.passphrase = None
        self.issuing_ca_name = None
        self.issuing_ca_key = None
        self.cert_validity_days = 365
        self.ca_cert_chain_list = []
        self.template_name = None
        self.header_info_field = None
        self.eab_handler = None
        self.eab_profiling = False

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        if not self.xdb_file:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _asn1_stream_parse(self, asn1_stream: str = None) -> Dict[str, str]:
        """ parse asn_string """

        self.logger.debug('CAhandler._asn1_stream_parse()')
        oid_dic = {
            "2.5.4.3": "commonName",
            "2.5.4.4": "surname",
            "2.5.4.5": "serialNumber",
            "2.5.4.6": "countryName",
            "2.5.4.7": "localityName",
            "2.5.4.8": "stateOrProvinceName",
            "2.5.4.9": "streetAddress",
            "2.5.4.10": "organizationName",
            "2.5.4.11": "organizationalUnitName",
            "2.5.4.12": "title",
            "2.5.4.13": "description",
            "2.5.4.42": "givenName",
        }

        dn_dic = {}
        if asn1_stream:

            # cut first 8 bytes which are bogus
            # asn1_stream = asn1_stream[8:]

            # split stream
            stream_list = asn1_stream.split(b'\x06\x03\x55')
            # we have to remove the first element from list as it contains junk
            stream_list.pop(0)

            for ele in stream_list:
                oid = f'2.5.{ele[0]}.{ele[1]}'
                if oid in oid_dic:
                    value_len = ele[3]
                    value = ele[4:4 + value_len]
                    dn_dic[oid_dic[oid]] = value.decode('utf-8')

            self.logger.debug('CAhandler._asn1_stream_parse() ended: %s', bool(dn_dic))
        return dn_dic

    def _ca_cert_load(self) -> Tuple[object, int]:
        """ load ca key from database """
        self.logger.debug('CAhandler._ca_cert_load({%s)', self.issuing_ca_name)

        # query database for key
        self._db_open()
        pre_statement = '''SELECT * from view_certs WHERE name LIKE ?'''
        self.cursor.execute(pre_statement, [self.issuing_ca_name])
        try:
            db_result = dict_from_row(self.cursor.fetchone())
        except Exception:
            self.logger.error('cert lookup failed: %s', self.cursor.fetchone())
            db_result = {}
        self._db_close()

        ca_cert = None
        ca_id = None

        if 'cert' in db_result:
            try:
                ca_cert = x509.load_der_x509_certificate(b64_decode(self.logger, db_result['cert']), backend=default_backend())
                ca_id = db_result['id']
            except Exception as err_:
                self.logger.error('CAhandler._ca_cert_load() failed with error: %s', err_)
        return (ca_cert, ca_id)

    def _ca_key_load(self) -> object:
        """ load ca key from database """
        self.logger.debug('CAhandler._ca_key_load(%s)', self.issuing_ca_key)

        # query database for key
        self._db_open()
        pre_statement = '''SELECT * from view_private WHERE name LIKE ?'''
        self.cursor.execute(pre_statement, [self.issuing_ca_key])
        try:
            db_result = dict_from_row(self.cursor.fetchone())
        except Exception as _err:
            self.logger.error('key lookup failed: %s', self.cursor.fetchone())
            db_result = {}
        self._db_close()

        ca_key = None
        if db_result and 'private' in db_result:
            try:
                private_key = f'-----BEGIN ENCRYPTED PRIVATE KEY-----\n{db_result["private"]}\n-----END ENCRYPTED PRIVATE KEY-----'
                ca_key = serialization.load_pem_private_key(convert_string_to_byte(private_key), password=convert_string_to_byte(self.passphrase), backend=default_backend())
            except Exception as err_:
                self.logger.error('CAhandler._ca_key_load() failed with error: %s', err_)
        else:
            self.logger.error('CAhandler._ca_key_load() failed to load key: %s', db_result)

        self.logger.debug('CAhandler._ca_key_load() ended')
        return ca_key

    def _ca_load(self) -> Tuple[object, object, int]:
        """ load ca key and cert """
        self.logger.debug('CAhandler._ca_load()')
        ca_key = self._ca_key_load()
        (ca_cert, ca_id) = self._ca_cert_load()

        self.logger.debug('CAhandler._ca_load() ended')
        return (ca_key, ca_cert, ca_id)

    def _cdp_list_generate(self, cdp_string: str = None) -> List[str]:
        """ generate cdp list """
        self.logger.debug('CAhandler._cdp_list_generate()')

        cdp_list = []
        if cdp_string:
            for ele in cdp_string.split(','):
                cdp_list.append(x509.DistributionPoint([x509.UniformResourceIdentifier(ele.strip())], crl_issuer=None, reasons=None, relative_name=None))

        self.logger.debug('CAhandler._cdp_list_generate() ended')
        return cdp_list

    def _cert_insert(self, cert_dic: Dict[str, str] = None) -> int:
        """ insert new entry to request table """
        self.logger.debug('CAhandler._cert_insert()')

        row_id = None
        if cert_dic:
            if all(key in cert_dic for key in ('item', 'serial', 'issuer', 'ca', 'cert', 'iss_hash', 'hash')):
                # pylint: disable=R0916
                if isinstance(cert_dic['item'], int) and isinstance(cert_dic['issuer'], int) and isinstance(cert_dic['ca'], int) and isinstance(cert_dic['iss_hash'], int) and isinstance(cert_dic['iss_hash'], int) and isinstance(cert_dic['hash'], int):
                    self._db_open()
                    self.cursor.execute('''INSERT INTO CERTS(item, serial, issuer, ca, cert, hash, iss_hash) VALUES(:item, :serial, :issuer, :ca, :cert, :hash, :iss_hash)''', cert_dic)
                    row_id = self.cursor.lastrowid
                    self._db_close()
                else:
                    self.logger.error('CAhandler._cert_insert() aborted. wrong datatypes: %s', cert_dic)
            else:
                self.logger.error('CAhandler._cert_insert() aborted. dataset incomplete: %s', cert_dic)
        else:
            self.logger.error('CAhandler._cert_insert() aborted. dataset empty')

        self.logger.debug('CAhandler._cert_insert() ended with row_id: %s', row_id)
        return row_id

    def _cert_search(self, column: str, value: str) -> Dict[str, str]:
        """ load ca key from database """
        self.logger.debug('CAhandler._cert_search({%s:%s)', column, value)

        # query database for key
        self._db_open()
        pre_statement = f'''SELECT * from items WHERE type == 3 and {column} LIKE ?'''
        self.cursor.execute(pre_statement, [value])

        cert_result = {}
        try:
            item_result = dict_from_row(self.cursor.fetchone())
        except Exception:
            self.logger.error('CAhandler._cert_search(): item search failed: %s', self.cursor.fetchone())
            item_result = {}

        if item_result:
            item_id = item_result['id']
            pre_statement = '''SELECT * from certs WHERE item LIKE ?'''
            self.cursor.execute(pre_statement, [item_id])
            try:
                cert_result = dict_from_row(self.cursor.fetchone())
            except Exception:
                self.logger.error('CAhandler._cert_search(): cert search failed: item: %s', item_id)

        self._db_close()
        self.logger.debug('CAhandler._cert_search() ended')
        return cert_result

    def _cert_subject_generate(self, req: object, request_name: str, dn_dic: Dict[str, str] = None) -> str:
        """ set subject """
        self.logger.debug('CAhandler._cert_subject_generate()')

        if not bool(req.subject):
            self.logger.info('rewrite CN to %s', request_name)
            subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, request_name)])
        else:
            subject = req.subject

        if dn_dic:
            # modify subject according to template
            subject = self._subject_modify(subject, dn_dic)

        self.logger.debug('CAhandler._cert_subject_generate() ended')
        return subject

    def _cert_sign(self, csr: str, request_name: str, ca_key: object, ca_cert: object, ca_id: int) -> Tuple[str, str]:  # pylint: disable=R0913
        self.logger.debug('Certificate._cert_sign()')

        # load template if configured
        if self.template_name:
            (dn_dic, template_dic) = self._template_load()
        else:
            dn_dic = {}
            template_dic = {}

        # creating a rest from CSR
        req = x509.load_pem_x509_csr(convert_string_to_byte(csr), default_backend())

        # set cert_validity
        if 'validity' in template_dic:
            self.logger.info('take validity from template: %s', template_dic['validity'])
            # take validity from template
            cert_validity = template_dic['validity']
        else:
            cert_validity = self.cert_validity_days

        # create object for certificate
        builder = x509.CertificateBuilder()

        # set not valid before
        builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        builder = builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=cert_validity))
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.serial_number(uuid.uuid4().int & (1 << 63) - 1)
        builder = builder.public_key(req.public_key())

        # get extension list from CSR
        csr_extensions_list = req.extensions
        extension_list = self._extension_list_generate(template_dic, req, ca_cert, csr_extensions_list)

        # add extensions (copy from CSR and take the ones we constructed)
        for extension in extension_list:
            builder = builder.add_extension(extension['name'], critical=extension['critical'])

        # get subject and set to builder
        builder = builder.subject_name(self._cert_subject_generate(req, request_name, dn_dic))

        # sign certificate
        cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256(), backend=default_backend())

        # get serial
        serial = cert.serial_number
        # get hsshes
        issuer_subject_hash = self._subject_name_hash_get(ca_cert)
        cert_subject_hash = self._subject_name_hash_get(cert)

        # store certificate
        self._store_cert(ca_id, request_name, f'{serial:X}', convert_byte_to_string(b64_encode(self.logger, cert.public_bytes(serialization.Encoding.DER))), cert_subject_hash, issuer_subject_hash)

        cert_bundle = self._pemcertchain_generate(convert_byte_to_string(cert.public_bytes(serialization.Encoding.PEM)), convert_byte_to_string(ca_cert.public_bytes(serialization.Encoding.PEM)))
        cert_raw = convert_byte_to_string(b64_encode(self.logger, cert.public_bytes(serialization.Encoding.DER)))

        self.logger.debug('Certificate._cert_sign() ended.')
        return (cert_bundle, cert_raw)

    def _config_check(self) -> str:
        """ check config for consitency """
        self.logger.debug('CAhandler._config_check()')
        error = None

        if self.xdb_file:
            if not os.path.exists(self.xdb_file):
                error = f'xdb_file {self.xdb_file} does not exist'
                self.xdb_file = None
        else:
            error = 'xdb_file must be specified in config file'

        if not error and not self.issuing_ca_name:
            error = 'issuing_ca_name must be set in config file'

        if error:
            self.logger.debug('CAhandler config error: %s', error)

        if not self.issuing_ca_key:
            self.logger.debug('use self.issuing_ca_name as self.issuing_ca_key: %s', self.issuing_ca_name)
            self.issuing_ca_key = self.issuing_ca_name

        self.logger.debug('CAhandler._config_check() ended')
        return error

    def _config_load(self):
        """" load config from file """
        self.logger.debug('CAhandler._config_load()')
        config_dic = load_config(self.logger, 'CAhandler')

        if 'xdb_file' in config_dic['CAhandler']:
            self.xdb_file = config_dic['CAhandler']['xdb_file']

        if 'passphrase_variable' in config_dic['CAhandler']:
            try:
                self.passphrase = os.environ[config_dic['CAhandler']['passphrase_variable']]
            except Exception as err:
                self.logger.error('CAhandler._config_load() could not load passphrase_variable:%s', err)

        if 'passphrase' in config_dic['CAhandler']:
            # overwrite passphrase specified in variable
            if self.passphrase:
                self.logger.info('CAhandler._config_load() overwrite passphrase_variable')
            self.passphrase = config_dic['CAhandler']['passphrase']

        if 'issuing_ca_name' in config_dic['CAhandler']:
            self.issuing_ca_name = config_dic['CAhandler']['issuing_ca_name']

        if 'issuing_ca_key' in config_dic['CAhandler']:
            self.issuing_ca_key = config_dic['CAhandler']['issuing_ca_key']

        if 'ca_cert_chain_list' in config_dic['CAhandler']:
            try:
                self.ca_cert_chain_list = json.loads(config_dic['CAhandler']['ca_cert_chain_list'])
            except Exception:
                self.logger.error('CAhandler._config_load(): parameter "ca_cert_chain_list" cannot be loaded')

        if 'template_name' in config_dic['CAhandler']:
            self.template_name = config_dic['CAhandler']['template_name']

        # load profiling
        self.eab_profiling, self.eab_handler = config_eab_profile_load(self.logger, config_dic)
        # load header info
        self.header_info_field = config_headerinfo_get(self.logger, config_dic)

    def _csr_import(self, csr, request_name):
        """ check existance of csr and load into db """
        self.logger.debug('CAhandler._csr_import()')

        csr_info = self._csr_search('request', csr)

        if not csr_info:

            # csr does not exist in db - lets import it
            insert_date = uts_to_date_utc(uts_now(), DEFAULT_DATE_FORMAT)
            item_dic = {'type': 2, 'comment': 'from acme2certifier', 'source': 2, 'date': insert_date, 'name': request_name}
            row_id = self._item_insert(item_dic)

            # insert csr
            csr_info = {'item': row_id, 'signed': 1, 'request': csr}
            self._csr_insert(csr_info)

        self.logger.debug('CAhandler._csr_import() ended')
        return csr_info

    def _csr_insert(self, csr_dic: Dict[str, str] = None) -> int:
        """ insert new entry to request table """
        self.logger.debug('CAhandler._csr_insert()')
        row_id = None
        if csr_dic:
            if all(key in csr_dic for key in ('item', 'signed', 'request')):
                # item and signed must be integer
                if isinstance(csr_dic['item'], int) and isinstance(csr_dic['signed'], int):
                    self._db_open()
                    self.cursor.execute('''INSERT INTO REQUESTS(item, signed, request) VALUES(:item, :signed, :request)''', csr_dic)
                    row_id = self.cursor.lastrowid
                    self._db_close()
                else:
                    self.logger.error('CAhandler._csr_insert() aborted. wrong datatypes: %s', csr_dic)
            else:
                self.logger.error('CAhandler._csr_insert() aborted. dataset incomplete: %s', csr_dic)
        else:
            self.logger.error('CAhandler._csr_insert() aborted. dataset empty')

        self.logger.debug('CAhandler._csr_insert() ended with row_id: %s', row_id)
        return row_id

    def _csr_search(self, column: str, value: str) -> Dict[str, str]:
        """ load ca key from database """
        self.logger.debug('CAhandler._csr_search()')

        # query database for key
        self._db_open()
        pre_statement = f'''SELECT * from view_requests WHERE {column} LIKE ?'''
        self.cursor.execute(pre_statement, [value])

        try:
            db_result = dict_from_row(self.cursor.fetchone())
        except Exception:
            db_result = {}
        self._db_close()
        self.logger.debug('CAhandler._csr_search() ended with: %s', bool(db_result))
        return db_result

    def _db_open(self):
        """ opens db and sets cursor """
        # pylint: disable=W0201
        self.dbs = sqlite3.connect(self.xdb_file)
        self.dbs.row_factory = sqlite3.Row
        # pylint: disable=W0201
        self.cursor = self.dbs.cursor()

    def _db_close(self):
        """ commit and close """
        # self.logger.debug('DBStore._db_close()')
        self.dbs.commit()
        self.dbs.close()
        # self.logger.debug('DBStore._db_close() ended')

    def _extended_keyusage_generate(self, template_dic: Dict[str, str], _csr_extensions_dic: Dict[str, str] = None) -> Tuple[bool, List[str]]:
        """ set generate extended key usage extenstion """
        self.logger.debug('CAhandler._extended_keyusage_generate()')

        eku_list = []
        if 'eKeyUse' in template_dic:
            # eku included in tempalate
            eku_mapping_dic = {
                'clientAuth': ExtendedKeyUsageOID.CLIENT_AUTH,
                'serverAuth': ExtendedKeyUsageOID.SERVER_AUTH,
                'codeSigning': ExtendedKeyUsageOID.CODE_SIGNING,
                'emailProtection': ExtendedKeyUsageOID.EMAIL_PROTECTION,
                'timeStamping': ExtendedKeyUsageOID.TIME_STAMPING,
                'OCSPSigning': ExtendedKeyUsageOID.OCSP_SIGNING,
                'pkInitKDC': ExtendedKeyUsageOID.KERBEROS_PKINIT_KDC,
                'eKeyUse': 'eKeyUse'  # this is just for testing
            }
            if 'ekuCritical' in template_dic:
                try:
                    ekuc = bool(int(template_dic['ekuCritical']))
                except Exception:
                    self.logger.error('CAhandler._extended_keyusage_generate(): convert to int failed defaulting ekuc to False')
                    ekuc = False
            else:
                ekuc = False

            for ele in template_dic['eKeyUse'].split(', '):
                if ele in eku_mapping_dic:
                    eku_list.append(eku_mapping_dic[ele])

        else:
            # neither extension nor template
            eku_list = None
            ekuc = False

        return (ekuc, eku_list)

    def _extension_list_default(self, ca_cert: str = None, cert: str = None):
        """ set default extension list """
        self.logger.debug('CAhandler._extension_list_default()')

        extension_list = [
            {'name': BasicConstraints(ca=False, path_length=None), 'critical': True},
            {'name': KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=False, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), 'critical': True},
            {'name': ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), 'critical': False},
        ]
        if cert:
            extension_list.append({'name': SubjectKeyIdentifier.from_public_key(cert.public_key()), 'critical': False},)
        if ca_cert:
            extension_list.append({'name': AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), 'critical': False})

        self.logger.debug('CAhandler._extension_list_default() ended')
        return extension_list

    def _extension_list_generate(self, template_dic: Dict[str, str], cert: str, ca_cert: str, csr_extensions_list: List[str] = None) -> List[str]:
        """ set extension list """
        self.logger.debug('CAhandler._extension_list_generate()')

        csr_extensions_dic = {}
        if csr_extensions_list:
            for ext in csr_extensions_list:
                csr_extensions_dic[convert_byte_to_string(ext.oid._name)] = ext  # pylint: disable=W0212

        if template_dic:
            # prcoess xca template
            extension_list = self._xca_template_process(template_dic, csr_extensions_dic, cert, ca_cert)
        else:
            extension_list = self._extension_list_default(ca_cert, cert)

        # add subjectAltName(s)
        if 'subjectAltName' in csr_extensions_dic:
            # pylint: disable=C2801
            self.logger.info('CAhandler._extension_list_generate(): adding subAltNames: %s', csr_extensions_dic['subjectAltName'].__str__())
            extension_list.append({'name': SubjectAlternativeName(csr_extensions_dic['subjectAltName'].value), 'critical': False})

        self.logger.debug('CAhandler._extension_list_generate() ended')
        return extension_list

    def _item_insert(self, item_dic: Dict[str, str] = None) -> int:
        """ insert new entry to item_table """
        self.logger.debug('CAhandler._item_insert()')
        row_id = None
        # insert
        if item_dic:
            if all(key in item_dic for key in ('name', 'type', 'source', 'date', 'comment')):
                if isinstance(item_dic['type'], int) and isinstance(item_dic['source'], int):
                    self._db_open()
                    self.cursor.execute('''INSERT INTO ITEMS(name, type, source, date, comment) VALUES(:name, :type, :source, :date, :comment)''', item_dic)
                    row_id = self.cursor.lastrowid
                    # update stamp field
                    data_dic = {'stamp': row_id}
                    self.cursor.execute('''UPDATE ITEMS SET stamp = :stamp WHERE id = :stamp''', data_dic)
                    self._db_close()
                else:
                    self.logger.error('CAhandler._insert_insert() aborted. wrong datatypes: %s', item_dic)
            else:
                self.logger.error('CAhandler._item_insert() aborted. dataset incomplete: %s', item_dic)
        else:
            self.logger.error('CAhandler._insert_insert() aborted. dataset empty')

        self.logger.debug('CAhandler._item_insert() ended with row_id: %s', row_id)
        return row_id

    def _keyusage_generate(self, template_dic: Dict[str, str], _csr_extensions_dic: Dict[str, str] = None) -> Tuple[bool, Dict[str, str]]:
        """ set generate key usage extenstion """
        self.logger.debug('CAhandler._keyusage_generate()')

        if 'keyUse' in template_dic:
            if 'kuCritical' in template_dic:
                try:
                    kuc = bool(int(template_dic['kuCritical']))
                except Exception:
                    kuc = False
            else:
                kuc = False
            kup = template_dic['keyUse']
        else:
            kuc = False
            kup = 0

        # generate key-usage extension
        ku_dic = self._kue_generate(kup)

        return (kuc, ku_dic)

    def _kue_generate(self, kuval: int = 0, ku_csr: str = None) -> Dict[str, str]:
        """ set generate key usage extension """
        self.logger.debug('CAhandler._kue_generate()')

        # convert keyusage value from template
        if kuval:
            try:
                kuval = int(kuval)
            except Exception:
                self.logger.error('CAhandler._kue_generate(): convert to int failed defaulting ku_val to 0')
                kuval = 0

        if kuval:
            # we have a key-usage value from template
            self.logger.info('CAhandler._kue_generate() with data from template')
            ku_dic = self._ku_dict_generate(kuval)
        elif ku_csr:
            # no data from template but data from csr
            self.logger.info('CAhandler._kue_generate() with data from csr')
            ku_dic = ku_csr
        else:
            # no data from template no data from csr - default (23)
            self.logger.info('CAhandler._kue_generate() with 23')
            ku_dic = self._ku_dict_generate(23)

        self.logger.debug('CAhandler._kue_generate() ended with: %s', ku_dic)
        return ku_dic

    def _ku_dict_generate(self, kuval: int = 0) -> Dict[str, str]:
        self.logger.debug('CAhandler._ku_dict_generate(%s)', kuval)

        # generate and reverse key_usage_list
        key_usage_list = ['digital_signature', 'content_commitment', 'key_encipherment', 'data_encipherment', 'key_agreement', 'key_cert_sign', 'crl_sign', 'encipher_only', 'decipher_only']
        key_usage_dic = {'digital_signature': False, 'content_commitment': False, 'key_encipherment': False, 'data_encipherment': False, 'key_agreement': False, 'key_cert_sign': False, 'crl_sign': False, 'encipher_only': False, 'decipher_only': False}

        kubin = f'{kuval:b}'[::-1]
        for idx, ele in enumerate(kubin):
            if ele == '1':
                key_usage_dic[key_usage_list[idx]] = True

        self.logger.debug('CAhandler._ku_dict_generate() ended with: %s', key_usage_dic)
        return key_usage_dic

    def _pemcertchain_generate(self, ee_cert: str, issuer_cert: str = None) -> str:
        """ build pem chain """
        self.logger.debug('CAhandler._pemcertchain_generate()')

        if issuer_cert:
            pem_chain = f'{ee_cert}{issuer_cert}'
        else:
            pem_chain = ee_cert

        for cert in self.ca_cert_chain_list:
            cert_dic = self._cert_search('items.name', cert)
            if cert_dic and 'cert' in cert_dic:
                ca_cert = x509.load_der_x509_certificate(b64_decode(self.logger, cert_dic['cert']), backend=default_backend())
                pem_chain = f'{pem_chain}{convert_byte_to_string(ca_cert.public_bytes(serialization.Encoding.PEM))}'

        self.logger.debug('CAhandler._pemcertchain_generate() ended')
        return pem_chain

    def _requestname_get(self, csr: str = None) -> str:
        """ get request name """
        self.logger.debug('CAhandler._requestname_get()')

        # try to get cn for a name in database
        request_name = csr_cn_get(self.logger, csr)
        if not request_name:
            san_list = csr_san_get(self.logger, csr)
            try:
                (_identifiier, request_name,) = san_list[0].split(':')
            except Exception:
                self.logger.error('ERROR: CAhandler._request_name_get(): SAN split failed: %s', san_list)

        self.logger.debug('CAhandler._requestname_get() ended with: %s', request_name)
        return request_name

    def _revocation_insert(self, rev_dic: Dict[str, str] = None) -> int:
        """ insert new entry to into revocation_table """
        self.logger.debug('CAhandler._revocation_insert()')
        row_id = None
        # insert
        if rev_dic:
            if all(key in rev_dic for key in ('caID', 'serial', 'date', 'invaldate', 'reasonBit')):
                if isinstance(rev_dic['caID'], int) and isinstance(rev_dic['reasonBit'], int):
                    self._db_open()
                    self.cursor.execute('''INSERT INTO REVOCATIONS(caID, serial, date, invaldate, reasonBit) VALUES(:caID, :serial, :date, :invaldate, :reasonBit)''', rev_dic)
                    row_id = self.cursor.lastrowid
                    self._db_close()
                else:
                    self.logger.error('CAhandler._revocation_insert() aborted. wrong datatypes: %s', rev_dic)
            else:
                self.logger.error('CAhandler._revocation_insert() aborted. dataset incomplete: %s', rev_dic)
        else:
            self.logger.error('CAhandler._revocation_insert() aborted. dataset empty')

        self.logger.debug('CAhandler._revocation_insert() ended with row_id: %s', row_id)
        return row_id

    def _revocation_check(self, serial: str, ca_id: int, err_msg_dic: Dict[str, str] = None) -> Tuple[int, str, str]:
        self.logger.debug('CAhandler.revoke(%s/%s)', serial, ca_id)

        # check if certificate has alreay been revoked:
        if not self._revocation_search('serial', serial):
            rev_dic = {'caID': ca_id, 'serial': serial, 'date': uts_to_date_utc(uts_now(), DEFAULT_DATE_FORMAT), 'invaldate': uts_to_date_utc(uts_now(), DEFAULT_DATE_FORMAT), 'reasonBit': 0}
            row_id = self._revocation_insert(rev_dic)
            if row_id:
                code = 200
                message = None
                detail = None
            else:
                code = 500
                message = err_msg_dic['serverinternal']
                detail = 'database update failed'
        else:
            code = 400
            message = err_msg_dic['alreadyrevoked']
            detail = 'Certificate has already been revoked'

        self.logger.debug('CAhandler.revoke() ended with: %s', code)
        return (code, message, detail)

    def _revocation_search(self, column: str, value: str) -> Dict[str, str]:
        """ load ca key from database """
        self.logger.debug('CAhandler._revocation_search()')
        # query database for key
        self._db_open()
        pre_statement = f'''SELECT * from revocations WHERE {column} LIKE ?'''
        self.cursor.execute(pre_statement, [value])

        try:
            db_result = dict_from_row(self.cursor.fetchone())
        except Exception:
            db_result = {}
        self._db_close()
        self.logger.debug('CAhandler._revocation_search() ended')
        return db_result

    # pylint: disable=R0913
    def _store_cert(self, ca_id: int, cert_name: str, serial: str, cert: str, name_hash: str, issuer_hash: str) -> int:
        """ store certificate to database """
        self.logger.debug('CAhandler._store_cert()')

        # insert certificate into item table
        insert_date = uts_to_date_utc(uts_now(), DEFAULT_DATE_FORMAT)
        item_dic = {'type': 3, 'comment': 'from acme2certifier', 'source': 2, 'date': insert_date, 'name': cert_name}
        row_id = self._item_insert(item_dic)
        # insert certificate to cert table
        cert_dic = {'item': row_id, 'serial': serial, 'issuer': ca_id, 'ca': 0, 'cert': cert, 'iss_hash': issuer_hash, 'hash': name_hash}
        _row_id = self._cert_insert(cert_dic)  # lgtm [py/unused-local-variable]

        self.logger.debug('CAhandler._store_cert() ended')

    def _stream_split(self, byte_stream: str = None) -> Tuple[str, str]:
        """ split template in asn1 structure and utf_stream """
        self.logger.debug('CAhandler._stream_split()')
        asn1_stream = None
        utf_stream = None

        # convert to byte if not already done
        byte_stream = convert_string_to_byte(byte_stream)

        if byte_stream:
            # search pattern
            pos = byte_stream.find(b'\x00\x00\x00\x0c') + 4
            if pos != 3:
                # split file 3 bcs find returns -1 in case of no-match
                asn1_stream = byte_stream[:pos]
                utf_stream = byte_stream[pos:]

        self.logger.debug('CAhandler._stream_split() ended: %s:%s', bool(asn1_stream), bool(utf_stream))
        return (asn1_stream, utf_stream)

    def _stub_func(self, parameter: str) -> str:
        """" load config from file """
        self.logger.debug('CAhandler._stub_func(%s)', parameter)
        self.logger.debug('CAhandler._stub_func() ended')
        return parameter

    def _subject_name_hash_get(self, cert: str = None) -> int:
        """ get subject name hash """
        self.logger.debug('CAhandler._subject_name_hash_get()')

        pyopenssl_cert = pyossslcrypto.X509.from_cryptography(cert)
        pyopenssl_subject_name_hash = pyopenssl_cert.subject_name_hash() & 0x7fffffff

        return pyopenssl_subject_name_hash

    def _subject_modify(self, subject: str, dn_dic: Dict[str, str] = None) -> str:
        """ modify subject name """
        self.logger.debug('CAhandler._subject_modify()')

        subject_name_list = []

        if 'organizationalUnitName' in dn_dic and dn_dic['organizationalUnitName']:
            self.logger.info('rewrite OU to %s', dn_dic['organizationalUnitName'])
            subject_name_list.append(x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, dn_dic['organizationalUnitName']))
        if 'organizationName' in dn_dic and dn_dic['organizationName']:
            self.logger.info('rewrite O to %s', dn_dic['organizationName'])
            subject_name_list.append(x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, dn_dic['organizationName']))
        if 'localityName' in dn_dic and dn_dic['localityName']:
            self.logger.info('rewrite L to %s', dn_dic['localityName'])
            subject_name_list.append(x509.NameAttribute(x509.NameOID.LOCALITY_NAME, dn_dic['localityName']))
        if 'stateOrProvinceName' in dn_dic and dn_dic['stateOrProvinceName']:
            self.logger.info('rewrite ST to %s', dn_dic['stateOrProvinceName'])
            subject_name_list.append(x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, dn_dic['stateOrProvinceName']))
        if 'countryName' in dn_dic and dn_dic['countryName']:
            self.logger.info('rewrite C to %s', dn_dic['countryName'])
            subject_name_list.append(x509.NameAttribute(x509.NameOID.COUNTRY_NAME, dn_dic['countryName']))

        if subject_name_list:
            subject = x509.Name([*subject, *subject_name_list])

        self.logger.debug('CAhandler._subject_modify() ended')
        return subject

    def _template_load(self) -> Tuple[Dict[str, str], Dict[str, str]]:
        """ load template from database """
        self.logger.debug('CAhandler._template_load(%s)', self.template_name)
        # query database for template
        self._db_open()
        pre_statement = '''SELECT * from view_templates WHERE name LIKE ?'''
        self.cursor.execute(pre_statement, [self.template_name])
        try:
            db_result = dict_from_row(self.cursor.fetchone())
        except Exception:
            self.logger.error('template lookup failed: %s', self.cursor.fetchone())
            db_result = {}

        # parse template
        dn_dic = {}
        template_dic = {}
        if 'template' in db_result:
            byte_stream = b64_decode(self.logger, db_result['template'])
            (dn_dic, template_dic) = self._template_parse(byte_stream)
        self._db_close()
        self.logger.debug('CAhandler._template_load() ended')

        return (dn_dic, template_dic)

    def _template_parse(self, byte_string: str = None) -> Tuple[Dict[str, str], Dict[str, str]]:
        """ process template """
        self.logger.debug('CAhandler._template_parse()')
        (asn1_stream, utf_stream) = self._stream_split(byte_string)

        dn_dic = {}
        if asn1_stream:
            dn_dic = self._asn1_stream_parse(asn1_stream)

        template_dic = {}
        if utf_stream:
            template_dic = self._utf_stream_parse(utf_stream)
            if template_dic:
                # replace '' with None
                template_dic = {k: None if not v else v for k, v in template_dic.items()}

                template_dic['validity'] = self._validity_calculate(template_dic)

        self.logger.debug('CAhandler._template_parse() ended')
        return (dn_dic, template_dic)

    def _utf_stream_parse(self, utf_stream: str = None) -> Dict[str, str]:
        """ parse template information from utf_stream into dictitionary """
        self.logger.debug('CAhandler._utf_stream_parse()')
        template_dic = {}

        if utf_stream:
            stream_list = utf_stream.split(b'\x00\x00\x00')

            # iterate list and clean up parameter
            parameter_list = []
            for idx, ele in enumerate(stream_list):
                ele = ele.replace(b'\x00', b'')
                if idx > 0:
                    # strip the first character
                    ele = ele[1:]
                if ele == b'eKeyUse\xff\xff\xff\xff':
                    self.logger.info('_utf_stream_parse(): hack to skip template with empty eku - maybe a bug in xca...')
                else:
                    parameter_list.append(ele.decode('utf-8'))

            if parameter_list:
                if len(parameter_list) % 2 != 0:
                    # remove last element from list if amount of list entries is uneven
                    parameter_list.pop()
                # convert list into a directory
                template_dic = {item: parameter_list[index + 1] for index, item in enumerate(parameter_list) if index % 2 == 0}

        self.logger.debug('CAhandler._utf_stream_parse() ended: %s', bool(template_dic))
        return template_dic

    def _validity_calculate(self, template_dic: Dict[str, str] = None) -> int:
        """ calculate validity in days """
        self.logger.debug('CAhandler._validity_calculate()')

        cert_validity = 365
        if 'validM' in template_dic and 'validN' in template_dic:
            if template_dic['validM'] == '0':
                # validity in days
                cert_validity = int(template_dic['validN'])
            elif template_dic['validM'] == '1':
                # validity in months
                cert_validity = int(template_dic['validN']) * 30
            elif template_dic['validM'] == '2':
                # validity in months
                cert_validity = int(template_dic['validN']) * 365
        else:
            cert_validity = 365

        self.logger.debug('CAhandler._validity_calculate() ended with: %s', cert_validity)
        return cert_validity

    def _xca_template_process(self, template_dic: Dict[str, str], csr_extensions_dic: Dict[str, str], cert: str, ca_cert: str) -> List[str]:
        """ add xca template """
        self.logger.debug('Certificate._xca_template_process()')

        extension_list = [
            {'name': SubjectKeyIdentifier.from_public_key(cert.public_key()), 'critical': False},
            {'name': AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), 'critical': False},
        ]

        # key_usage
        (kuc, ku_dic) = self._keyusage_generate(template_dic, csr_extensions_dic)
        extension_list.append({'name': KeyUsage(**ku_dic), 'critical': kuc})

        # extended key_usage
        (ekuc, eku_list) = self._extended_keyusage_generate(template_dic, csr_extensions_dic)
        if eku_list:
            extension_list.append({'name': ExtendedKeyUsage(eku_list), 'critical': ekuc})

        # add cdp
        if 'crlDist' in template_dic and template_dic['crlDist']:
            cdp_list = self._cdp_list_generate(template_dic['crlDist'])
            extension_list.append({'name': x509.CRLDistributionPoints(cdp_list), 'critical': False})

        # add basicConstraints
        if 'ca' in template_dic:
            if 'bcCritical' in template_dic:
                try:
                    bcc = bool(int(template_dic['bcCritical']))
                except Exception:
                    bcc = False
            else:
                bcc = False

            if template_dic['ca'] == '1':
                extension_list.append({'name': BasicConstraints(ca=True, path_length=None), 'critical': bcc})
            elif template_dic['ca'] == '2':
                extension_list.append({'name': BasicConstraints(ca=False, path_length=None), 'critical': bcc})

        return extension_list

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
        if hasattr(self, key):
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

            # we need to cover cases where profiling is enabled but no profile_id is defined in json
            if self.header_info_field and handler_hifield not in eab_profile_dic:
                hil_value = header_info_lookup(self.logger, csr, self.header_info_field, handler_hifield)
                if hil_value:
                    setattr(self, handler_hifield, hil_value)

        self.logger.debug('CAhandler._eab_profile_check() ended with: %s', result)
        return result

    def _profile_check(self, csr: str) -> str:
        """ check profile """
        self.logger.debug('CAhandler._profile_check()')
        error = None

        # handler specific header info field
        handler_hifield = "template_name"

        if self.eab_profiling:
            if self.eab_handler:
                error = self._eab_profile_check(csr, handler_hifield)
                # we need to cover cases where handler_value is enabled but nothing is defined in json
            elif self.header_info_field:
                # no profiling - parse profileid from http_header
                hil_value = header_info_lookup(self.logger, csr, self.header_info_field, handler_hifield)
                if hil_value:
                    self.logger.debug('CAhandler._profile_check(): setting %s to %s', handler_hifield, hil_value)
                    # self.template_name = hil_value
                    setattr(self, handler_hifield, hil_value)
            else:
                self.logger.error('CAhandler._profile_check(): eab_profiling enabled but no handler defined')

        self.logger.debug('CAhandler._profile_check() ended with %s', error)
        return error

    def enroll(self, csr: str = None) -> Tuple[str, str, str, str]:
        """ enroll certificate  """
        # pylint: disable=R0914, R0915
        self.logger.debug('CAhandler.enroll()')

        cert_bundle = None
        cert_raw = None
        error = self._config_check()

        if not error:
            error = self._profile_check(csr)

        if not error:
            request_name = self._requestname_get(csr)

            if request_name:
                # import CSR to database
                _csr_info = self._csr_import(csr, request_name)  # lgtm [py/unused-local-variable]

                # prepare the CSR to be signed
                csr = build_pem_file(self.logger, None, b64_url_recode(self.logger, csr), None, True)

                # load ca cert and key
                (ca_key, ca_cert, ca_id) = self._ca_load()

                if ca_key and ca_cert and ca_id:
                    (cert_bundle, cert_raw) = self._cert_sign(csr, request_name, ca_key, ca_cert, ca_id)
                else:
                    error = 'ca lookup failed'
            else:
                error = 'request_name lookup failed'
        self.logger.debug('Certificate.enroll() ended')
        return (error, cert_bundle, cert_raw, None)

    def poll(self, cert_name: str, poll_identifier: str, _csr: str) -> Tuple[str, str, str, str, bool]:
        """ poll status of pending CSR and download certificates """
        self.logger.debug('CAhandler.poll()')

        error = 'Method not implemented.'
        cert_bundle = None
        cert_raw = None
        rejected = False
        self._stub_func(cert_name)

        self.logger.debug('CAhandler.poll() ended')
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(self, cert: str, _rev_reason: str = 'unspecified', _rev_date: str = None) -> Tuple[int, str, str]:
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke()')

        err_msg_dic = error_dic_get(self.logger)

        if self.xdb_file:
            # load ca cert and key
            (_ca_key, _ca_cert, ca_id) = self._ca_load()

            serial = cert_serial_get(self.logger, cert)
            if serial:
                serial = f'{serial:X}'

            if ca_id and serial:
                (code, message, detail) = self._revocation_check(serial, ca_id, err_msg_dic)
            else:
                code = 500
                message = err_msg_dic['serverinternal']
                detail = 'certificate lookup failed'
        else:
            code = 500
            message = err_msg_dic['serverinternal']
            detail = 'configuration error'

        self.logger.debug('Certificate.revoke() ended')
        return (code, message, detail)

    def trigger(self, payload: str) -> Tuple[str, str, str]:
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')

        error = 'Method not implemented.'
        cert_bundle = None
        cert_raw = None
        self._stub_func(payload)

        self.logger.debug('CAhandler.trigger() ended with error: %s', error)
        return (error, cert_bundle, cert_raw)
