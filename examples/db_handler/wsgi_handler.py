#!/usr/bin/python
# -*- coding: utf-8 -*-
""" cgi handler for acmesrv.py """
from __future__ import print_function
import sqlite3
import json
import os
from acme.helper import datestr_to_date

def dict_from_row(row):
    """ small helper to convert the output of a "select" command into a dictionary """
    return dict(zip(row.keys(), row))

class DBstore(object):
    """ helper to do datebase operations """

    def __init__(self, debug=False, logger=None, db_name=os.path.dirname(__file__)+'/'+'acme_srv.db'):
        """ init """
        self.db_name = db_name
        self.debug = debug
        self.logger = logger
        self.dbs = None
        self.cursor = None

        if not os.path.exists(self.db_name):
            self.db_create()

    def account_add(self, data_dic):
        """ add account in database """
        self.logger.debug('DBStore.account_add({0})'.format(data_dic))

        # we need this for compability with django
        created = False
        # check if we alredy have an entry for the key
        exists = self.account_search('jwk', data_dic['jwk'])
        self.db_open()
        if bool(exists):
            # update
            aname = exists[1]
            self.logger.debug('account exists: {0} id: {1}'.format(aname, exists[0]))
            self.cursor.execute('''UPDATE ACCOUNT SET alg = :alg, jwk = :jwk, contact = :contact WHERE jwk = :jwk''', data_dic)
        else:
            # insert
            self.cursor.execute('''INSERT INTO ACCOUNT(alg, jwk, contact, name) VALUES(:alg, :jwk, :contact, :name)''', data_dic)
            aname = data_dic['name']
            created = True

        self.db_close()
        self.logger.debug('DBStore.account_add() ended')
        return(aname, created)

    def account_delete(self, aname):
        """ add account in database """
        self.logger.debug('DBStore.account_delete({0})'.format(aname))
        self.db_open()
        pre_statement = 'DELETE FROM account WHERE name LIKE ?'
        self.cursor.execute(pre_statement, [aname])
        result = bool(self.cursor.rowcount)
        self.db_close()
        self.logger.debug('DBStore.account_delete() ended')
        return result

    def account_lookup(self, column, string):
        """ lookup account table for a certain key/value pair and return id"""
        self.logger.debug('DBStore.account_lookup(column:{0}, pattern:{1})'.format(column, string))
        try:
            result = dict_from_row(self.account_search(column, string))
        except BaseException:
            result = {}
        if 'created_at' in result:
            result['created_at'] = datestr_to_date(result['created_at'], '%Y-%m-%d %H:%M:%S')
        self.logger.debug('DBStore.account_lookup() ended')
        return result

    def account_search(self, column, string):
        """ search account table for a certain key/value pair """
        self.logger.debug('DBStore.account_search(column:{0}, pattern:{1})'.format(column, string))
        self.db_open()
        pre_statement = 'SELECT * from account WHERE {0} LIKE ?'.format(column)
        self.cursor.execute(pre_statement, [string])
        result = self.cursor.fetchone()
        self.db_close()
        self.logger.debug('DBStore.account_search() ended')
        return result

    def account_update(self, data_dic):
        """ update existing account """
        self.logger.debug('DBStore.account_update({0})'.format(data_dic))

        lookup = dict_from_row(self.account_search('name', data_dic['name']))
        if lookup:
            if 'alg' not in data_dic:
                data_dic['alg'] = lookup['alg']
            if 'contact' not in data_dic:
                data_dic['contact'] = lookup['contact']
            if 'jwk' not in data_dic:
                data_dic['jwk'] = lookup['jwk']

            self.db_open()
            self.cursor.execute('''UPDATE account SET alg = :alg, contact = :contact, jwk = :jwk WHERE name = :name''', data_dic)
            self.cursor.execute('''SELECT id FROM account WHERE name=:name''', {'name': data_dic['name']})
            result = self.cursor.fetchone()[0]
            self.db_close()
        else:
            result = None
        self.logger.debug('DBStore.account_update() ended')
        return result

    def authorization_add(self, data_dic):
        """ add authorization to database """
        self.logger.debug('DBStore.authorization_add({0})'.format(data_dic))
        self.db_open()
        self.cursor.execute('''INSERT INTO authorization(name, order_id, type, value) VALUES(:name, :order, :type, :value)''', data_dic)
        rid = self.cursor.lastrowid
        self.db_close()
        self.logger.debug('DBStore.authorization_add() ended with: {0}'.format(rid))
        return rid

    def authorization_lookup(self, column, string, vlist=('type', 'value')):
        """ search account for a given id """
        self.logger.debug('DBStore.authorization_lookup(column:{0}, pattern:{1})'.format(column, string))

        try:
            lookup = self.authorization_search(column, string)
        except BaseException:
            lookup = []

        authz_list = []
        for row in lookup:
            row_dic = dict_from_row(row)
            tmp_dic = {}
            for ele in vlist:
                tmp_dic[ele] = row_dic[ele]
            authz_list.append(tmp_dic)
        self.logger.debug('DBStore.authorization_lookup() ended')
        return authz_list

    def authorization_search(self, column, string):
        """ search account table for a certain key/value pair """
        self.logger.debug('DBStore.authorization_search(column:{0}, pattern:{1})'.format(column, string))
        if column == 'name':
            self.logger.debug('rename name to authorization.name')
            column = 'authorization.name'
        self.db_open()
        pre_statement = '''SELECT
                            authorization.*,
                            orders.id as orders__id,
                            orders.name as order__name,
                            status.id as status_id,
                            status.name as status__name,
                            account.name as order__account__name
                        from authorization
                        INNER JOIN orders on orders.id = authorization.order_id
                        INNER JOIN status on status.id = authorization.status_id
                        INNER JOIN account on account.id = orders.account_id
                        WHERE {0} LIKE ?'''.format(column)
        self.cursor.execute(pre_statement, [string])
        result = self.cursor.fetchall()
        self.db_close()
        self.logger.debug('DBStore.authorization_search() ended')
        return result

    def authorization_update(self, data_dic):
        """ update existing authorization """
        self.logger.debug('DBStore.authorization_update({0})'.format(data_dic))

        lookup = self.authorization_search('name', data_dic['name'])
        if lookup:
            lookup = dict_from_row(lookup[0])
            if 'status' in data_dic:
                data_dic['status'] = dict_from_row(self.status_search('name', data_dic['status']))['id']
            else:
                data_dic['status'] = lookup['status_id']
            if 'token' not in data_dic:
                data_dic['token'] = lookup['token']
            if 'expires' not in data_dic:
                data_dic['expires'] = lookup['expires']

            self.db_open()
            self.cursor.execute('''UPDATE authorization SET status_id = :status, token = :token, expires = :expires WHERE name = :name''', data_dic)
            self.cursor.execute('''SELECT id FROM authorization WHERE name=:name''', {'name': data_dic['name']})
            result = self.cursor.fetchone()[0]
            self.db_close()
        else:
            result = None
        self.logger.debug('DBStore.authorization_update() ended')
        return result

    def certificate_account_check(self, account_name, certificate):
        """ check issuer against certificate """
        self.logger.debug('DBStore.certificate_account_check({0})'.format(account_name))

        # search certificate table to get the order-id
        certificate_dic = self.certificate_lookup('cert_raw', certificate, ['name', 'order__name'])

        result = None

        # search order table to get the account-name based on the order-id
        if 'order__name' in certificate_dic:
            order_dic = self.order_lookup('name', certificate_dic['order__name'], ['name', 'account__name'])
            if order_dic:
                if 'account__name' in order_dic:
                    if account_name:
                        # if there is an acoount name validate it against the account_name from db-query
                        if order_dic['account__name'] == account_name:
                            result = certificate_dic['order__name']
                            self.logger.debug('message signed with account key')
                        else:
                            self.logger.debug('account_name and and account_name from oder differ.')
                    else:
                        # no account name given (message signed with domain key)
                        result = certificate_dic['order__name']
                        self.logger.debug('message signed with domain key')
                else:
                    self.logger.debug('account_name missing in order_dic')
            else:
                self.logger.debug('order_dic empty')

        self.logger.debug('DBStore.certificate_account_check() ended with: {0}'.format(result))
        return result

    def certificate_add(self, data_dic):
        """ add csr/certificate to database """
        self.logger.debug('DBStore.certificate_add({0})'.format(data_dic['name']))
        # check if we alredy have an entry for the key
        exists = self.certificate_search('name', data_dic['name'])

        if bool(exists):
            # update
            self.logger.debug('update existing entry for {0} id:{1}'.format(data_dic['name'], dict_from_row(exists)['id']))
            self.db_open()
            if 'error' in data_dic:
                self.cursor.execute('''UPDATE Certificate SET error = :error, poll_identifier = :poll_identifier WHERE name = :name''', data_dic)
            else:
                self.cursor.execute('''UPDATE Certificate SET cert = :cert, cert_raw = :cert_raw WHERE name = :name''', data_dic)
            self.db_close()
            rid = dict_from_row(exists)['id']
        else:
            # insert
            self.logger.debug('insert new entry for {0}'.format(data_dic['name']))
            # change order name to id but tackle cases where we cannot do this
            try:
                data_dic['order'] = dict_from_row(self.order_search('name', data_dic['order']))['id']
            except BaseException:
                data_dic['order'] = 0

            self.db_open()
            if not 'csr' in data_dic:
                data_dic['csr'] = ''
            if 'error' in data_dic:
                self.cursor.execute('''INSERT INTO Certificate(name, error, order_id, csr) VALUES(:name, :error, :order, :csr)''', data_dic)
            else:
                self.cursor.execute('''INSERT INTO Certificate(name, csr, order_id) VALUES(:name, :csr, :order)''', data_dic)
            self.db_close()
            rid = self.cursor.lastrowid
        self.logger.debug('DBStore.certificate_add() ended with: {0}'.format(rid))
        return rid

    def certificate_lookup(self, column, string, vlist=('name', 'csr', 'cert', 'order__name')):
        """ search certificate based on "something" """
        self.logger.debug('DBstore.certificate_lookup({0}:{1})'.format(column, string))

        try:
            lookup = dict_from_row(self.certificate_search(column, string))
        except BaseException:
            lookup = None

        result = {}
        if lookup:
            for ele in vlist:
                result[ele] = lookup[ele]
                if ele == 'order__name':
                    result['order'] = lookup[ele]
        else:
            result = {}

        self.logger.debug('DBStore.certificate_lookup() ended with: {0}'.format(result))
        return result

    def certificate_search(self, column, string):
        """ search certificate table for a certain key/value pair """
        self.logger.debug('DBStore.certificate_search(column:{0}, pattern:{1})'.format(column, string))
        self.db_open()

        if column != 'order__name':
            column = 'certificate.{0}'.format(column)
            self.logger.debug('modified column to {0}'.format(column))

        pre_statement = '''SELECT certificate.*,
                            orders.id as order__id,
                            orders.name as order__name,
                            orders.status_id as order__status_id,
                            account.name as order__account__name
                            from certificate
                            INNER JOIN orders on orders.id = certificate.order_id
                            INNER JOIN account on account.id = orders.account_id
                            WHERE {0} LIKE ?'''.format(column)
        self.cursor.execute(pre_statement, [string])
        result = self.cursor.fetchone()
        self.db_close()
        self.logger.debug('DBStore.certificate_search() ended')
        return result

    def certificates_search(self, column, string, vlist=('name', 'csr', 'cert', 'order__name')):
        """ search certificate table for a certain key/value pair """
        self.logger.debug('DBStore.certificate_search(column:{0}, pattern:{1})'.format(column, string))
        self.db_open()

        if column == 'order__status_id':
            column = 'orders.status_id'
            self.logger.debug('modified column to {0}'.format(column))

        pre_statement = '''SELECT certificate.*,
                            orders.id as order__id,
                            orders.name as order__name,
                            orders.status_id as order__status_id,
                            account.name as order__account__name
                            from certificate
                            INNER JOIN orders on orders.id = certificate.order_id
                            INNER JOIN account on account.id = orders.account_id
                            WHERE {0} LIKE ?'''.format(column)
        self.cursor.execute(pre_statement, [string])

        rows = self.cursor.fetchall()

        cert_list = []
        for row in rows:
            lookup = dict_from_row(row)
            result = {}
            if lookup:
                for ele in vlist:
                    result[ele] = lookup[ele]
                    if ele == 'order__name':
                        result['order'] = lookup[ele]
            cert_list.append(result)

        self.db_close()
        self.logger.debug('DBStore.certificate_search() ended')
        return cert_list


    def challenge_add(self, data_dic):
        """ add challenge to database """
        self.logger.debug('DBStore.challenge_add({0})'.format(data_dic))
        authorization = self.authorization_lookup('name', data_dic['authorization'], ['id'])

        if not "status" in data_dic:
            data_dic['status'] = 2
        if authorization:
            data_dic['authorization'] = authorization[0]['id']
            self.db_open()
            self.cursor.execute('''INSERT INTO challenge(name, token, authorization_id, expires, type, status_id) VALUES(:name, :token, :authorization, :expires, :type, :status)''', data_dic)
            rid = self.cursor.lastrowid
            self.db_close()
        else:
            rid = None
        self.logger.debug('DBStore.challenge_add() ended')
        return rid

    def challenge_lookup(self, column, string, vlist=('type', 'token', 'status__name')):
        """ search account for a given id """
        self.logger.debug('challenge_lookup({0}:{1})'.format(column, string))

        try:
            lookup = dict_from_row(self.challenge_search(column, string))
        except BaseException:
            lookup = None

        result = {}
        if lookup:
            for ele in vlist:
                if ele == 'status__name':
                    result['status'] = lookup['status__name']
                elif ele == 'authorization__name':
                    result['authorization'] = lookup['authorization__name']
                else:
                    result[ele] = lookup[ele]
        else:
            result = None
        self.logger.debug('DBStore.challenge_lookup() ended with:{0}'.format(result))
        return result

    def challenge_search(self, column, string):
        """ search challenge table for a certain key/value pair """
        self.logger.debug('DBStore.challenge_search(column:{0}, pattern:{1})'.format(column, string))
        self.db_open()
        pre_statement = '''
            SELECT
                challenge.*,
                status.id as status__id,
                status.name as status__name,
                authorization.id as authorization__id,
                authorization.name as authorization__name,
                authorization.type as authorization__type,
                authorization.value as authorization__value,
                authorization.token as authorization__token,
                orders.name as authorization__order__name,
                account.name as authorization__order__account__name
            from challenge
            INNER JOIN status on status.id = challenge.status_id
            INNER JOIN authorization on authorization.id = challenge.authorization_id
            INNER JOIN orders on orders.id = authorization.order_id
            INNER JOIN account on account.id = orders.account_id
            WHERE challenge.{0} LIKE ?'''.format(column)
        self.cursor.execute(pre_statement, [string])
        result = self.cursor.fetchone()
        self.db_close()
        self.logger.debug('DBStore.challenge_search() ended')
        return result

    def challenge_update(self, data_dic):
        """ update challenge """
        self.logger.debug('challenge_update({0})'.format(data_dic))
        lookup = self.challenge_search('name', data_dic['name'])
        lookup = dict_from_row(lookup)

        if 'status' in data_dic:
            data_dic['status'] = dict_from_row(self.status_search('name', data_dic['status']))['id']
        else:
            data_dic['status'] = lookup['status__id']

        if 'keyauthorization' not in data_dic:
            data_dic['keyauthorization'] = lookup['keyauthorization']

        self.db_open()
        self.cursor.execute('''UPDATE challenge SET status_id = :status, keyauthorization = :keyauthorization WHERE name = :name''', data_dic)
        self.db_close()
        self.logger.debug('DBStore.challenge_update() ended')

    def db_close(self):
        """ commit and close """
        self.logger.debug('DBStore.db_close()')
        self.dbs.commit()
        self.dbs.close()
        self.logger.debug('DBStore.db_close() ended')

    def db_create(self):
        """ create the database if dos not exist """
        self.logger.debug('DBStore.db_create({0})'.format(self.db_name))
        self.db_open()
        # create nonce table
        self.logger.debug('create nonce')
        self.cursor.execute('''
            CREATE TABLE "nonce" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "nonce" varchar(30) NOT NULL, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
        ''')
        self.logger.debug('create account')
        self.cursor.execute('''
            CREATE TABLE "account" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(15) NOT NULL UNIQUE, "alg" varchar(10) NOT NULL, "jwk" TEXT UNIQUE NOT NULL, "contact" TEXT NOT NULL, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
        ''')
        self.logger.debug('create status')
        self.cursor.execute('''
            CREATE TABLE "status" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(15) UNIQUE NOT NULL)
        ''')
        self.cursor.execute('''INSERT INTO status(name) VALUES(:name)''', {'name': 'invalid'})
        self.cursor.execute('''INSERT INTO status(name) VALUES(:name)''', {'name': 'pending'})
        self.cursor.execute('''INSERT INTO status(name) VALUES(:name)''', {'name': 'ready'})
        self.cursor.execute('''INSERT INTO status(name) VALUES(:name)''', {'name': 'processing'})
        self.cursor.execute('''INSERT INTO status(name) VALUES(:name)''', {'name': 'valid'})
        self.logger.debug('create orders')
        self.cursor.execute('''
            CREATE TABLE "orders" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(15) UNIQUE NOT NULL, "notbefore" integer DEFAULT 0, "notafter" integer DEFAULT 0, "identifiers" varchar(1048) NOT NULL, "account_id" integer NOT NULL REFERENCES "account" ("id"), "status_id" integer NOT NULL REFERENCES "status" ("id") DEFAULT 2, "expires" integer NOT NULL, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
        ''')
        self.logger.debug('create authorization')
        self.cursor.execute('''
            CREATE TABLE "authorization" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(15) NOT NULL UNIQUE, "order_id" integer NOT NULL REFERENCES "order" ("id"), "type" varchar(5) NOT NULL, "value" varchar(64) NOT NULL, "expires" integer, "token" varchar(64), "status_id" integer NOT NULL REFERENCES "status" ("id") DEFAULT 2, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
        ''')
        self.logger.debug('create challenge')
        self.cursor.execute('''
            CREATE TABLE "challenge" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(15) NOT NULL UNIQUE, "token" varchar(64), "authorization_id" integer NOT NULL REFERENCES "authorization" ("id"), "expires" integer, "type" varchar(10) NOT NULL, "keyauthorization" varchar(128), "status_id" integer NOT NULL REFERENCES "status" ("id"), "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
        ''')
        self.logger.debug('create certificate')
        self.cursor.execute('''
            CREATE TABLE "certificate" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(15) NOT NULL UNIQUE, "cert" text, "cert_raw" text, "error" text, "order_id" integer NOT NULL REFERENCES "order" ("id"), "csr" text NOT NULL, "poll_identifier" text, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
        ''')

        self.db_close()
        self.logger.debug('DBStore.db_create() ended')

    def db_open(self):
        """ opens db and sets cursor """
        self.logger.debug('DBStore.db_open()')
        self.dbs = sqlite3.connect(self.db_name)
        self.dbs.row_factory = sqlite3.Row
        self.cursor = self.dbs.cursor()
        self.logger.debug('DBStore.db_open() ended')

    def db_update(self):
        """ update database """
        self.logger.debug('DBStore.db_update()')
        self.db_open()
        # add poll_identifier if not existing
        self.cursor.execute('''PRAGMA table_info(certificate)''')
        certificate_column_list = []
        for column in self.cursor.fetchall():
            certificate_column_list.append(column[1])

        if 'poll_identifier' not in certificate_column_list:
            self.logger.debug('alter certificate table - add poll_identifier')
            self.cursor.execute('''ALTER TABLE certificate ADD COLUMN poll_identifier text''')

        self.db_close()

        self.logger.debug('DBStore.db_update() ended')

    def jwk_load(self, aname):
        """ looad account informatino and build jwk key dictionary """
        self.logger.debug('DBStore.jwk_load({0})'.format(aname))
        account_list = self.account_search('name', aname)
        jwk_dict = {}
        if account_list:
            jwk_dict = json.loads(account_list[3])
            jwk_dict['alg'] = account_list[2]
        self.logger.debug('DBStore.jwk_load() ended')
        return jwk_dict

    def nonce_add(self, nonce):
        """ check if nonce is in datbase
        in: nonce
        return: rowid """
        self.logger.debug('DBStore.nonce_add({0})'.format(nonce))
        self.db_open()
        self.cursor.execute('''INSERT INTO nonce(nonce) VALUES(:nonce)''', {'nonce': nonce})
        rid = self.cursor.lastrowid
        self.db_close()
        self.logger.debug('DBStore.nonce_add() ended')
        return rid

    def nonce_check(self, nonce):
        """ ceck if nonce is in datbase
        in: nonce
        return: true in case nonce exit, otherwise false """
        self.logger.debug('DBStore.nonce_check({0})'.format(nonce))
        self.db_open()
        self.cursor.execute('''SELECT nonce FROM nonce WHERE nonce=:nonce''', {'nonce': nonce})
        result = bool(self.cursor.fetchone())
        self.db_close()
        self.logger.debug('DBStore.nonce_check() ended')
        return result

    def nonce_delete(self, nonce):
        """ delete nonce from datbase
        in: nonce """
        self.logger.debug('DBStore.nonce_delete({0})'.format(nonce))
        self.db_open()
        self.cursor.execute('''DELETE FROM nonce WHERE nonce=:nonce''', {'nonce': nonce})
        self.db_close()
        self.logger.debug('DBStore.nonce_delete() ended')

    def order_add(self, data_dic):
        """ add order to database """
        self.logger.debug('DBStore.order_add({0})'.format(data_dic))
        if 'notbefore' not in data_dic:
            data_dic['notbefore'] = ''

        if 'notafter' not in data_dic:
            data_dic['notafter'] = ''

        account = self.account_lookup('name', data_dic['account'])
        if account:
            data_dic['account'] = account['id']
            self.db_open()
            self.cursor.execute('''INSERT INTO orders(name, identifiers, account_id, status_id, expires, notbefore, notafter) VALUES(:name, :identifiers, :account, :status, :expires, :notbefore, :notafter )''', data_dic)
            rid = self.cursor.lastrowid
            self.db_close()
        else:
            rid = None
        self.logger.debug('DBStore.order_add() ended')
        return rid

    def order_lookup(self, column, string, vlist=('notbefore', 'notafter', 'identifiers', 'expires', 'status__name')):
        """ search orders for a given ordername """
        self.logger.debug('order_lookup({0}:{1})'.format(column, string))

        try:
            lookup = dict_from_row(self.order_search(column, string))
        except BaseException:
            lookup = None

        result = {}
        if lookup:
            # small hack (not sure db returnsblank and not 0)
            if lookup['notafter'] == '':
                lookup['notafter'] = 0
            if lookup['notbefore'] == '':
                lookup['notbefore'] = 0
            for ele in vlist:
                if ele == 'status__name':
                    result['status'] = lookup['status__name']
                else:
                    result[ele] = lookup[ele]
        else:
            result = None
        self.logger.debug('DBStore.order_lookup() ended with: {0}'.format(result))
        return result

    def order_search(self, column, string):
        """ search order table for a certain key/value pair """
        self.logger.debug('DBStore.order_search(column:{0}, pattern:{1})'.format(column, string))
        self.db_open()
        pre_statement = '''
                    SELECT
                        orders.*,
                        status.name as status__name,
                        status.id as status__id,
                        account.name as account__name,
                        account.id as account_id
                    from orders
                    INNER JOIN status on status.id = orders.status_id
                    INNER JOIN account on account.id = orders.account_id
                    WHERE orders.{0} LIKE ?'''.format(column)
        self.cursor.execute(pre_statement, [string])
        result = self.cursor.fetchone()
        self.db_close()
        self.logger.debug('DBStore.order_search() ended')
        return result

    def order_update(self, data_dic):
        """ update order """
        self.logger.debug('order_update({0})'.format(data_dic))
        if 'status' in data_dic:
            data_dic['status'] = dict_from_row(self.status_search('name', data_dic['status']))['id']
        self.db_open()
        self.cursor.execute('''UPDATE orders SET status_id = :status WHERE name = :name''', data_dic)
        self.db_close()
        self.logger.debug('DBStore.order_update() ended')

    def status_search(self, column, string):
        """ search status table for a certain key/value pair """
        self.logger.debug('DBStore.status_search(column:{0}, pattern:{1})'.format(column, string))
        self.db_open()
        pre_statement = 'SELECT * from status WHERE status.{0} LIKE ?'.format(column)
        self.cursor.execute(pre_statement, [string])
        result = self.cursor.fetchone()
        self.db_close()
        self.logger.debug('DBStore.status_search() ended')
        return result
