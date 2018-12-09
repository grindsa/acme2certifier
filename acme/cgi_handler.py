#!/usr/bin/python
# -*- coding: utf-8 -*-
""" cgi handler for acmesrv.py """
from __future__ import print_function
import sqlite3
import os
from acme.helper import print_debug

class DBstore(object):
    """ helper to do datebase operations """

    def __init__(self, debug=False):
        """ init """
        self.db_name = 'acme.db'
        self.debug = debug
        self.dbs = None
        self.cursor = None

        if not os.path.exists(self.db_name):
            self.db_create()

    def db_close(self):
        """ commit and close """
        print_debug(self.debug, 'DBStore.db_close()')
        self.dbs.commit()
        self.dbs.close()

    def db_create(self):
        """ create the database if dos not exist """
        print_debug(self.debug, 'DBStore.db_create({0})'.format(self.db_name))
        self.db_open()
        # create nonce table
        self.cursor.execute('''
            CREATE TABLE "nonce" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "nonce" varchar(30) NOT NULL, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
        ''')
        self.db_close()

    def db_open(self):
        """ opens db and sets cursor """
        print_debug(self.debug, 'DBStore.db_open()')
        self.dbs = sqlite3.connect(self.db_name)
        self.cursor = self.dbs.cursor()

    def nonce_add(self, nonce):
        """ check if nonce is in datbase
        in: nonce
        return: rowid """
        print_debug(self.debug, 'DBStore.nonce_add({0})'.format(nonce))
        self.db_open()
        self.cursor.execute('''INSERT INTO nonce(nonce) VALUES(:nonce)''', {'nonce': nonce})
        rid = self.cursor.lastrowid
        self.db_close()
        return rid

    def nonce_check(self, nonce):
        """ ceck if nonce is in datbase
        in: nonce
        return: true in case nonce exit, otherwise false """
        print_debug(self.debug, 'DBStore.nonce_check({0})'.format(nonce))
        self.db_open()
        self.cursor.execute('''SELECT nonce FROM nonce WHERE nonce=:nonce''', {'nonce': nonce})
        result = bool(self.cursor.fetchone())
        self.db_close()
        return result

    def nonce_delete(self, nonce):
        """ delete nonce from datbase
        in: nonce """
        print_debug(self.debug, 'DBStore.nonce_delete({0})'.format(nonce))
        self.db_open()
        self.cursor.execute('''delete FROM nonce WHERE nonce=:nonce''', {'nonce': nonce})
        self.db_close()
