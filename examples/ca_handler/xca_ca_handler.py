#!/usr/bin/python
# -*- coding: utf-8 -*-
""" handler for xca handler """
from __future__ import print_function
import os
import sqlite3
import uuid
import json
from OpenSSL import crypto
# pylint: disable=C0209, E0401
from acme_srv.helper import load_config, build_pem_file, uts_now, uts_to_date_utc, b64_encode, b64_decode, b64_url_recode, cert_serial_get, convert_string_to_byte, convert_byte_to_string, csr_cn_get, csr_san_get, error_dic_get


def dict_from_row(row):
    """ small helper to convert the output of a "select" command into a dictionary """
    return dict(zip(row.keys(), row))


class CAhandler(object):
    """ CA  handler """

    def __init__(self, debug=None, logger=None):
        self.debug = debug
        self.logger = logger
        self.xdb_file = None
        self.passphrase = None
        self.issuing_ca_name = None
        self.issuing_ca_key = None
        self.cert_validity_days = 365
        self.ca_cert_chain_list = []
        self.template_name = None

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        if not self.xdb_file:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _asn1_stream_parse(self, asn1_stream=None):
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
                oid = '2.5.{0}.{1}'.format(ele[0], ele[1])
                if oid in oid_dic:
                    value_len = ele[3]
                    value = ele[4:4 + value_len]
                    dn_dic[oid_dic[oid]] = value.decode('utf-8')

            self.logger.debug('CAhandler._asn1_stream_parse() ended: {0}'.format(bool(dn_dic)))
        return dn_dic

    def _ca_cert_load(self):
        """ load ca key from database """
        self.logger.debug('CAhandler._ca_cert_load({0})'.format(self.issuing_ca_name))

        # query database for key
        self._db_open()
        pre_statement = '''SELECT * from view_certs WHERE name LIKE ?'''
        self.cursor.execute(pre_statement, [self.issuing_ca_name])
        try:
            db_result = dict_from_row(self.cursor.fetchone())
        except Exception:
            self.logger.error('cert lookup failed: {0}'.format(self.cursor.fetchone()))
            db_result = {}
        self._db_close()

        ca_cert = None
        ca_id = None

        if 'cert' in db_result:
            try:
                ca_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, b64_decode(self.logger, db_result['cert']))
                ca_id = db_result['id']
            except Exception as err_:
                self.logger.error('CAhandler._ca_cert_load() failed with error: {0}'.format(err_))
        return (ca_cert, ca_id)

    def _ca_key_load(self):
        """ load ca key from database """
        self.logger.debug('CAhandler._ca_key_load({0})'.format(self.issuing_ca_key))

        # query database for key
        self._db_open()
        pre_statement = '''SELECT * from view_private WHERE name LIKE ?'''
        self.cursor.execute(pre_statement, [self.issuing_ca_key])
        try:
            db_result = dict_from_row(self.cursor.fetchone())
        except Exception as _err:
            self.logger.error('key lookup failed: {0}'.format(self.cursor.fetchone()))
            db_result = {}
        self._db_close()

        ca_key = None
        if db_result and 'private' in db_result:
            try:
                private_key = '-----BEGIN ENCRYPTED PRIVATE KEY-----\n{0}\n-----END ENCRYPTED PRIVATE KEY-----'.format(db_result['private'])
                ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key, convert_string_to_byte(self.passphrase))

            except Exception as err_:
                self.logger.error('CAhandler._ca_key_load() failed with error: {0}'.format(err_))
        else:
            self.logger.error('CAhandler._ca_key_load() failed to load key: {0}'.format(db_result))

        self.logger.debug('CAhandler._ca_key_load() ended')
        return ca_key

    def _ca_load(self):
        """ load ca key and cert """
        self.logger.debug('CAhandler._ca_load()')
        ca_key = self._ca_key_load()
        (ca_cert, ca_id) = self._ca_cert_load()

        self.logger.debug('CAhandler._ca_load() ended')
        return (ca_key, ca_cert, ca_id)

    def _config_check(self):
        """ check config for consitency """
        self.logger.debug('CAhandler._config_check()')
        error = None

        if self.xdb_file:
            if not os.path.exists(self.xdb_file):
                error = 'xdb_file {0} does not exist'.format(self.xdb_file)
                self.xdb_file = None
        else:
            error = 'xdb_file must be specified in config file'

        if not error and not self.issuing_ca_name:
            error = 'issuing_ca_name must be set in config file'

        if error:
            self.logger.debug('CAhandler config error: {0}'.format(error))

        if not self.issuing_ca_key:
            self.logger.debug('use self.issuing_ca_name as self.issuing_ca_key: {0}'.format(self.issuing_ca_name))
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
                self.logger.error('CAhandler._config_load() could not load passphrase_variable:{0}'.format(err))

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

    def _csr_import(self, csr, request_name):
        """ check existance of csr and load into db """
        self.logger.debug('CAhandler._csr_import()')

        csr_info = self._csr_search('request', csr)

        if not csr_info:

            # csr does not exist in db - lets import it
            insert_date = uts_to_date_utc(uts_now(), '%Y%m%d%H%M%SZ')
            item_dic = {'type': 2, 'comment': 'from acme2certifier', 'source': 2, 'date': insert_date, 'name': request_name}
            row_id = self._item_insert(item_dic)

            # insert csr
            csr_info = {'item': row_id, 'signed': 1, 'request': csr}
            self._csr_insert(csr_info)

        self.logger.debug('CAhandler._csr_import() ended')
        return csr_info

    def _cert_insert(self, cert_dic):
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
                    self.logger.error('CAhandler._cert_insert() aborted. wrong datatypes: {}'.format(cert_dic))
            else:
                self.logger.error('CAhandler._cert_insert() aborted. dataset incomplete: {}'.format(cert_dic))
        else:
            self.logger.error('CAhandler._cert_insert() aborted. dataset empty')

        self.logger.debug('CAhandler._cert_insert() ended with row_id: {0}'.format(row_id))
        return row_id

    def _cert_search(self, column, value):
        """ load ca key from database """
        self.logger.debug('CAhandler._cert_search({0}:{1})'.format(column, value))

        # query database for key
        self._db_open()
        pre_statement = '''SELECT * from items WHERE type == 3 and {0} LIKE ?'''.format(column)
        self.cursor.execute(pre_statement, [value])

        cert_result = {}
        try:
            item_result = dict_from_row(self.cursor.fetchone())
        except Exception:
            self.logger.error('CAhandler._cert_search(): item search failed: {0}'.format(self.cursor.fetchone()))
            item_result = {}

        if item_result:
            item_id = item_result['id']
            pre_statement = '''SELECT * from certs WHERE item LIKE ?'''
            self.cursor.execute(pre_statement, [item_id])
            try:
                cert_result = dict_from_row(self.cursor.fetchone())
            except Exception:
                self.logger.error('CAhandler._cert_search(): cert search failed: item: {0}'.format(item_id))

        self._db_close()
        self.logger.debug('CAhandler._cert_search() ended')
        return cert_result

    def _csr_insert(self, csr_dic):
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
                    self.logger.error('CAhandler._csr_insert() aborted. wrong datatypes: {}'.format(csr_dic))
            else:
                self.logger.error('CAhandler._csr_insert() aborted. dataset incomplete: {}'.format(csr_dic))
        else:
            self.logger.error('CAhandler._csr_insert() aborted. dataset empty')

        self.logger.debug('CAhandler._csr_insert() ended with row_id: {0}'.format(row_id))
        return row_id

    def _csr_search(self, column, value):
        """ load ca key from database """
        self.logger.debug('CAhandler._csr_search()')

        # query database for key
        self._db_open()
        pre_statement = '''SELECT * from view_requests WHERE {0} LIKE ?'''.format(column)
        self.cursor.execute(pre_statement, [value])

        try:
            db_result = dict_from_row(self.cursor.fetchone())
        except Exception:
            db_result = {}
        self._db_close()
        self.logger.debug('CAhandler._csr_search() ended')
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

    def _extended_keyusage_generate(self, template_dic, csr_extensions_dic=None):
        """ set generate extended key usage extenstion """
        self.logger.debug('CAhandler._extended_keyusage_generate()')

        if 'eKeyUse' in template_dic:
            # eku included in tempalate
            if 'ekuCritical' in template_dic:
                try:
                    ekuc = bool(int(template_dic['ekuCritical']))
                except Exception:
                    ekuc = False
            else:
                ekuc = False
            eku_string = template_dic['eKeyUse']

        elif 'extendedKeyUsage' in csr_extensions_dic:
            # eku usage in extention
            try:
                ekuc = csr_extensions_dic['extendedKeyUsage'].get_critical()
            except Exception:
                ekuc = False
            # pylint: disable=C2801
            eku_string = csr_extensions_dic['extendedKeyUsage'].__str__()

        else:
            # neither extension nor template
            eku_string = None
            ekuc = False

        return (ekuc, eku_string)

    def _item_insert(self, item_dic):
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
                    self.logger.error('CAhandler._insert_insert() aborted. wrong datatypes: {}'.format(item_dic))
            else:
                self.logger.error('CAhandler._item_insert() aborted. dataset incomplete: {}'.format(item_dic))
        else:
            self.logger.error('CAhandler._insert_insert() aborted. dataset empty')

        self.logger.debug('CAhandler._item_insert() ended with row_id: {0}'.format(row_id))
        return row_id

    def _keyusage_generate(self, template_dic, csr_extensions_dic=None):
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

        if 'keyUsage' in csr_extensions_dic:
            # get key usage field csr
            # pylint: disable=C2801
            ku_csr = csr_extensions_dic['keyUsage'].__str__()
        else:
            ku_csr = None

        # generate key-usage extension
        ku_string = self._kue_generate(kup, ku_csr)

        return (kuc, ku_string)

    def _kue_generate(self, kuval=0, ku_csr=None):
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
            ku_string = self._ku_string_generate(kuval)
        elif ku_csr:
            # no data from template but data from csr
            self.logger.info('CAhandler._kue_generate() with data from csr')
            ku_string = ku_csr
        else:
            # no data from template no data from csr - default (23)
            self.logger.info('CAhandler._kue_generate() with 23')
            ku_string = self._ku_string_generate(23)

        self.logger.debug('CAhandler._kue_generate() ended with: {0}'.format(ku_string))
        return ku_string

    def _ku_string_generate(self, kuval):
        self.logger.debug('CAhandler._ku_string_generate({0})'.format(kuval))

        # generate and reverse key_usage_list
        key_usage_list = ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly']

        kubin = '{0:b}'.format(kuval)[::-1]
        ku_list = []
        for idx, ele in enumerate(kubin):
            if ele == '1':
                ku_list.append(key_usage_list[idx])
        ku_string = ','.join(ku_list)

        self.logger.debug('CAhandler._ku_string_generate() endedt with: {0}'.format(ku_string))
        return ku_string

    def _pemcertchain_generate(self, ee_cert, issuer_cert):
        """ build pem chain """
        self.logger.debug('CAhandler._pemcertchain_generate()')

        if issuer_cert:
            pem_chain = '{0}{1}'.format(ee_cert, issuer_cert)
        else:
            pem_chain = ee_cert

        for cert in self.ca_cert_chain_list:
            cert_dic = self._cert_search('items.name', cert)
            if cert_dic and 'cert' in cert_dic:
                ca_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, b64_decode(self.logger, cert_dic['cert']))
                pem_chain = '{0}{1}'.format(pem_chain, convert_byte_to_string(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert)))

        self.logger.debug('CAhandler._pemcertchain_generate() ended')
        return pem_chain

    def _requestname_get(self, csr):
        """ enroll certificate  """
        self.logger.debug('CAhandler._request_name_get()')

        # try to get cn for a name in database
        request_name = csr_cn_get(self.logger, csr)
        if not request_name:
            san_list = csr_san_get(self.logger, csr)
            try:
                (_identifiier, request_name,) = san_list[0].split(':')
            except Exception:
                self.logger.error('ERROR: CAhandler._request_name_get(): SAN split failed: {0}'.format(san_list))

        self.logger.debug('CAhandler._request_name_get() ended with: {0}'.format(request_name))
        return request_name

    def _revocation_insert(self, rev_dic):
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
                    self.logger.error('CAhandler._revocation_insert() aborted. wrong datatypes: {}'.format(rev_dic))
            else:
                self.logger.error('CAhandler._revocation_insert() aborted. dataset incomplete: {}'.format(rev_dic))
        else:
            self.logger.error('CAhandler._revocation_insert() aborted. dataset empty')

        self.logger.debug('CAhandler._revocation_insert() ended with row_id: {0}'.format(row_id))
        return row_id

    def _revocation_check(self, serial, ca_id, err_msg_dic):
        self.logger.debug('CAhandler.revoke({0}/{1})'.format(serial, ca_id))
        # check if certificate has alreay been revoked:
        if not self._revocation_search('serial', serial):
            rev_dic = {'caID': ca_id, 'serial': serial, 'date': uts_to_date_utc(uts_now(), '%Y%m%d%H%M%SZ'), 'invaldate': uts_to_date_utc(uts_now(), '%Y%m%d%H%M%SZ'), 'reasonBit': 0}
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

        self.logger.debug('CAhandler.revoke() ended with: {0}'.format(code))
        return (code, message, detail)

    def _revocation_search(self, column, value):
        """ load ca key from database """
        self.logger.debug('CAhandler._revocation_search()')
        # query database for key
        self._db_open()
        pre_statement = '''SELECT * from revocations WHERE {0} LIKE ?'''.format(column)
        self.cursor.execute(pre_statement, [value])

        try:
            db_result = dict_from_row(self.cursor.fetchone())
        except Exception:
            db_result = {}
        self._db_close()
        self.logger.debug('CAhandler._revocation_search() ended')
        return db_result

    # pylint: disable=R0913
    def _store_cert(self, ca_id, cert_name, serial, cert, name_hash, issuer_hash):
        """ store certificate to database """
        self.logger.debug('CAhandler._store_cert()')

        # insert certificate into item table
        insert_date = uts_to_date_utc(uts_now(), '%Y%m%d%H%M%SZ')
        item_dic = {'type': 3, 'comment': 'from acme2certifier', 'source': 2, 'date': insert_date, 'name': cert_name}
        row_id = self._item_insert(item_dic)
        # insert certificate to cert table
        cert_dic = {'item': row_id, 'serial': serial, 'issuer': ca_id, 'ca': 0, 'cert': cert, 'iss_hash': issuer_hash, 'hash': name_hash}
        _row_id = self._cert_insert(cert_dic)  # lgtm [py/unused-local-variable]

        self.logger.debug('CAhandler._store_cert() ended')

    def _stream_split(self, byte_stream):
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

        self.logger.debug('CAhandler._stream_split() ended: {0}:{1}'.format(bool(asn1_stream), bool(utf_stream)))
        return (asn1_stream, utf_stream)

    def _stub_func(self, parameter):
        """" load config from file """
        self.logger.debug('CAhandler._stub_func({0})'.format(parameter))
        self.logger.debug('CAhandler._stub_func() ended')
        return parameter

    def _subject_modify(self, subject, dn_dic):
        """ modify subject name """
        self.logger.debug('CAhandler._subject_modify()')

        if 'organizationalUnitName' in dn_dic and dn_dic['organizationalUnitName']:
            subject.organizationalUnitName = dn_dic['organizationalUnitName']
        if 'organizationName' in dn_dic and dn_dic['organizationName']:
            subject.organizationName = dn_dic['organizationName']
        if 'localityName' in dn_dic and dn_dic['localityName']:
            subject.localityName = dn_dic['localityName']
        if 'stateOrProvinceName' in dn_dic and dn_dic['stateOrProvinceName']:
            subject.stateOrProvinceName = dn_dic['stateOrProvinceName']
        if 'countryName' in dn_dic and dn_dic['countryName']:
            subject.countryName = dn_dic['countryName']

        self.logger.debug('CAhandler._subject_modify() ended')
        return subject

    def _template_load(self):
        """ load template from database """
        self.logger.debug('CAhandler._template_load({0})'.format(self.template_name))
        # query database for template
        self._db_open()
        pre_statement = '''SELECT * from view_templates WHERE name LIKE ?'''
        self.cursor.execute(pre_statement, [self.template_name])
        try:
            db_result = dict_from_row(self.cursor.fetchone())
        except Exception:
            self.logger.error('template lookup failed: {0}'.format(self.cursor.fetchone()))
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

    def _template_parse(self, byte_string=None):
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

    def _utf_stream_parse(self, utf_stream=None):
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

        self.logger.debug('CAhandler._utf_stream_parse() ended: {0}'.format(bool(template_dic)))
        return template_dic

    def _validity_calculate(self, template_dic):
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

        self.logger.debug('CAhandler._validity_calculate() ended with: {0}'.format(cert_validity))
        return cert_validity

    def _xca_template_process(self, template_dic, csr_extensions_dic, cert, ca_cert):
        """ add xca template """
        self.logger.debug('Certificate._xca_template_process()')
        extension_list = [
            crypto.X509Extension(convert_string_to_byte('subjectKeyIdentifier'), False, convert_string_to_byte('hash'), subject=cert),
            crypto.X509Extension(convert_string_to_byte('authorityKeyIdentifier'), False, convert_string_to_byte('keyid:always'), issuer=ca_cert),
        ]

        # key_usage
        (kuc, ku_string) = self._keyusage_generate(template_dic, csr_extensions_dic)
        extension_list.append(crypto.X509Extension(convert_string_to_byte('keyUsage'), kuc, convert_string_to_byte(ku_string)))

        # extended key_usage
        (ekuc, eku_string) = self._extended_keyusage_generate(template_dic, csr_extensions_dic)
        if eku_string:
            extension_list.append(crypto.X509Extension(convert_string_to_byte('extendedKeyUsage'), ekuc, convert_string_to_byte(eku_string)))

        # add cdp
        if 'crlDist' in template_dic and template_dic['crlDist']:
            extension_list.append(crypto.X509Extension(convert_string_to_byte('crlDistributionPoints'), False, convert_string_to_byte(template_dic['crlDist'])))

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
                extension_list.append(crypto.X509Extension(convert_string_to_byte('basicConstraints'), bcc, convert_string_to_byte('CA:TRUE')))
            elif template_dic['ca'] == '2':
                extension_list.append(crypto.X509Extension(convert_string_to_byte('basicConstraints'), bcc, convert_string_to_byte('CA:FALSE')))

        return extension_list

    def _cert_sign(self, csr, request_name, ca_key, ca_cert, ca_id):
        self.logger.debug('Certificate._cert_sign()')
        # load request
        req = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)

        # copy cn of request
        subject = req.get_subject()
        # rewrite CN if required
        if not subject.CN:
            self.logger.info('rewrite CN to {0}'.format(request_name))
            subject.CN = request_name

        # create certificate object
        cert = crypto.X509()
        cert.set_pubkey(req.get_pubkey())
        cert.set_version(2)
        cert.set_serial_number(uuid.uuid4().int & (1 << 63) - 1)
        cert.set_issuer(ca_cert.get_subject())

        # load template if configured
        if self.template_name:
            (dn_dic, template_dic) = self._template_load()
        else:
            dn_dic = {}
            template_dic = {}

        # set cert_validity
        if 'validity' in template_dic:
            self.logger.info('take validity from template: {0}'.format(template_dic['validity']))
            # take validity from template
            cert_validity = template_dic['validity']
        else:
            cert_validity = self.cert_validity_days
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(cert_validity * 86400)

        # get extension list from CSR
        csr_extensions_list = req.get_extensions()
        extension_list = self._extension_list_generate(template_dic, cert, ca_cert, csr_extensions_list)

        # add extensions (copy from CSR and take the ones we constructed)
        # cert.add_extensions(csr_extensions_list)
        cert.add_extensions(extension_list)

        if dn_dic:
            self.logger.info('modify subject with template data')
            subject = self._subject_modify(subject, dn_dic)
        cert.set_subject(subject)

        # sign csr
        cert.sign(ca_key, 'sha256')
        serial = cert.get_serial_number()

        # get hsshes
        issuer_hash = ca_cert.subject_name_hash() & 0x7fffffff
        name_hash = cert.subject_name_hash() & 0x7fffffff

        # store certificate
        self._store_cert(ca_id, request_name, '{:X}'.format(serial), convert_byte_to_string(b64_encode(self.logger, crypto.dump_certificate(crypto.FILETYPE_ASN1, cert))), name_hash, issuer_hash)

        cert_bundle = self._pemcertchain_generate(convert_byte_to_string(crypto.dump_certificate(crypto.FILETYPE_PEM, cert)), convert_byte_to_string(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert)))
        cert_raw = convert_byte_to_string(b64_encode(self.logger, crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)))

        self.logger.debug('Certificate._cert_sign() ended.')
        return (cert_bundle, cert_raw)

    def enroll(self, csr):
        """ enroll certificate  """
        # pylint: disable=R0914, R0915
        self.logger.debug('CAhandler.enroll()')

        cert_bundle = None
        cert_raw = None
        error = self._config_check()

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

    def _extension_list_generate(self, template_dic, cert, ca_cert, csr_extensions_list):
        """ set extension list """
        self.logger.debug('CAhandler._extension_list_generate()')

        csr_extensions_dic = {}
        for ext in csr_extensions_list:
            csr_extensions_dic[convert_byte_to_string(ext.get_short_name())] = ext

        if template_dic:
            # prcoess xca template
            extension_list = self._xca_template_process(template_dic, csr_extensions_dic, cert, ca_cert)
        else:
            default_extension_list = [
                crypto.X509Extension(convert_string_to_byte('subjectKeyIdentifier'), False, convert_string_to_byte('hash'), subject=cert),
                crypto.X509Extension(convert_string_to_byte('authorityKeyIdentifier'), False, convert_string_to_byte('keyid:always'), issuer=ca_cert),
                crypto.X509Extension(convert_string_to_byte('keyUsage'), True, convert_string_to_byte('digitalSignature,keyEncipherment')),
                crypto.X509Extension(convert_string_to_byte('basicConstraints'), True, convert_string_to_byte('CA:FALSE')),
                crypto.X509Extension(convert_string_to_byte('extendedKeyUsage'), False, convert_string_to_byte('serverAuth')),
                # crypto.X509Extension(convert_string_to_byte('extendedKeyUsage'), False, convert_string_to_byte('clientAuth,serverAuth')),
            ]
            extension_list = default_extension_list

        # add subjectAltName(s)
        if 'subjectAltName' in csr_extensions_dic:
            # pylint: disable=C2801
            self.logger.info('CAhandler._extension_list_generate(): adding subAltNames: {0}'.format(csr_extensions_dic['subjectAltName'].__str__()))
            extension_list.append(csr_extensions_dic['subjectAltName'])

        self.logger.debug('CAhandler._extension_list_generate() ended')
        return extension_list

    def poll(self, cert_name, poll_identifier, _csr):
        """ poll status of pending CSR and download certificates """
        self.logger.debug('CAhandler.poll()')

        error = 'Method not implemented.'
        cert_bundle = None
        cert_raw = None
        rejected = False
        self._stub_func(cert_name)

        self.logger.debug('CAhandler.poll() ended')
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(self, cert, _rev_reason='unspecified', _rev_date=None):
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke()')

        err_msg_dic = error_dic_get(self.logger)

        if self.xdb_file:
            # load ca cert and key
            (_ca_key, _ca_cert, ca_id) = self._ca_load()

            serial = cert_serial_get(self.logger, cert)
            if serial:
                serial = '{:X}'.format(serial)

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

    def trigger(self, payload):
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')

        error = 'Method not implemented.'
        cert_bundle = None
        cert_raw = None
        self._stub_func(payload)

        self.logger.debug('CAhandler.trigger() ended with error: {0}'.format(error))
        return (error, cert_bundle, cert_raw)
