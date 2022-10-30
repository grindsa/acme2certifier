#!/usr/bin/python3
# -*- coding: utf-8 -*-
# pylint: disable=c0209
""" acme2certifier cli client """
import logging
import datetime
import re
import argparse
import os.path
import sys
import time
import random
from string import digits, ascii_letters
import json
import csv
from jwcrypto import jwk, jws
from jwcrypto.common import json_encode
import requests

VERSION = "0.0.1"

CLI_INTRO = """acme2certifier command-line interface

Copyright (c) 2022 GrindSa

This software is provided free of charge. Copying and redistribution is
encouraged.

If you appreciate this software and you would like to support future
development please consider donating to me.

Type /help for available commands
"""


def csv_dump(logger, filename, content):
    """ dump content csv file """
    logger.debug('csv_dump({0})'.format(filename))
    with open(filename, 'w', newline='', encoding='utf-8') as file_:
        writer = csv.writer(file_, delimiter=',', quotechar='"', quoting=csv.QUOTE_NONNUMERIC)
        writer.writerows(content)


def generate_random_string(logger, length):
    """ generate random string to be used as name """
    logger.debug('generate_random_string()')
    char_set = digits + ascii_letters
    return ''.join(random.choice(char_set) for _ in range(length))


def file_dump(logger, filename, data_):
    """ dump content to  file """
    logger.debug('file_dump({0})'.format(filename))
    with open(filename, 'w', encoding='utf8') as file_:
        file_.write(data_)  # lgtm [py/clear-text-storage-sensitive-data]


def file_load(logger, filename):
    """ load file at once """
    logger.debug('file_open({0})'.format(filename))
    with open(filename, encoding='utf8') as _file:
        lines = _file.read()
    return lines


def is_url(string):
    """ check if sting is a valid url """
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    return re.match(regex, string)


def logger_setup(debug):
    """ setup logger """
    if debug:
        log_mode = logging.DEBUG
    else:
        log_mode = logging.INFO

    log_format = '%(asctime)s - a2c_cli - %(levelname)s - %(message)s'

    logging.basicConfig(
        format=log_format,
        datefmt="%Y-%m-%d %H:%M:%S",
        level=log_mode)
    logger = logging.getLogger('a2c_cli')
    return logger


class KeyOperations(object):
    """ key operations class """
    def __init__(self, logger=None, printcommand=None):
        # CLIParser(self)
        self.logger = logger
        self.print = printcommand

    def generate(self, filename):
        """ generate and store key """
        self.logger.debug('KeyOperations.generate({0})'.format(filename))
        self.print('generating keys...', printreturn=False)
        key = jwk.JWK.generate(kty='RSA', size=2048, alg='RSA-OAEP-256', use='sig', kid=generate_random_string(self.logger, 12))
        public_key = key.export_public(as_dict=True)
        private_key = key.export_private(as_dict=True)

        try:
            file_dump(self.logger, '{0}.pub'.format(filename), json.dumps(public_key, indent=4, sort_keys=True))
            file_dump(self.logger, '{0}.private'.format(filename), json.dumps(private_key, indent=4, sort_keys=True))
            self.print('done...', printreturn=False)
            self.print('Keep the private key {0}.pub for yourself'.format(filename), printreturn=False)
            self.print('Give the public key {0}.pub to your acme2certifier administrator'.format(filename))
        except Exception as err_:
            self.logger.error('KeyOperations.generate() failed with err: {0}'.format(err_))
            self.print('Key generation failed with error: {0}'.format(err_))
        return key

    def load(self, filename):
        """ load existing key """
        self.logger.debug('KeyOperations.load({0})'.format(filename))
        if os.path.exists(filename):
            self.print('loading {0}'.format(filename), printreturn=False)
            content = file_load(self.logger, filename)
            key = jwk.JWK.from_json(content)
            self.print('done...', printreturn=False)
        else:
            self.print('Could not find {0}'.format(filename))
            key = None
        return key


class MessageOperations(object):
    """ message operations class """
    def __init__(self, logger=None, printcommand=None):
        # CLIParser(self)
        self.logger = logger
        self.print = printcommand

    def sign(self, key, data, type='Unknown'):
        """ sign message """
        self.logger.debug('MessageOperations.sign()')
        protected = {"typ": "JOSE+JSON",
                     "kid": key['kid'],
                     "alg": "RS256"}
        plaintext = {"data": data, 'type': type,
                     "exp": int(time.time()) + (5 * 60)}
        mjws = jws.JWS(payload=json_encode(plaintext))
        mjws.add_signature(key, None, json_encode(protected))
        return mjws.serialize()

    def send(self, server=None, message=None):
        """ send message """
        self.logger.debug('MessageOperations.send({0})'.format(server))
        req = requests.post('{0}/housekeeping'.format(server), data=message, timeout=20)
        return req


class CommandLineInterface(object):
    """ cli class """
    def __init__(self):
        # CLIParser(self)
        parser = argparse.ArgumentParser()

        parser.add_argument("-d", "--debug",
                            action="store_true",
                            help="Show debug messages",
                            dest='debug',)

        parser.add_argument("-b", "--batchfile",
                            action='store',
                            help='batch file to execute',
                            dest='batchfile',)
        results = parser.parse_args()

        self.logger = logger_setup(results.debug)
        self.status = 'server missing'
        self.server = None
        self.key = None

        if results.batchfile:
            self._load_cfg(results.batchfile)

    def _load_cfg(self, ifile):
        """ load config """
        self.logger.debug('CommandLineInterface._load_cfg()')

        with open(ifile, 'r', encoding='utf8') as fha:
            for lin in fha:
                line = lin.rstrip()
                if line.startswith('sleep'):
                    try:
                        (_sleep, tme) = line.split(' ', 1)
                        time.sleep(int(tme))
                    except Exception:
                        time.sleep(1)
                else:
                    if line.startswith('#') is False:
                        self._command_check(line)

    def _cli_print(self, text, date_print=True, printreturn=True):
        """ cli printout text """
        self.logger.debug('CommandLineInterface._cli_print()')
        if text:
            if date_print:
                now = datetime.datetime.now().strftime('%H:%M:%S')
                if printreturn:
                    print('{0} {1}\n'.format(now, text))
                else:
                    print('{0} {1}'.format(now, text))
            else:
                print(text)

    def _command_check(self, command):
        """ check command """
        # pylint: disable=c0325
        self.logger.debug('CommandLineInterface._commend_check(): {0}'.format(command))
        if command in ('help', 'H'):
            self.help_print()
        elif command.startswith('server'):
            self._server_set(command)
        elif command.startswith('key'):
            self._key_operations(command)
        elif command.startswith('config'):
            self._config_operations(command)
        elif (command in ('quit', 'Q')):
            self._quit()
        elif self.status == 'Configured':
            if command.startswith('message'):
                self._message_operations(command)
            elif command.startswith('report'):
                self._report_operations(command)
            elif command.startswith('certificate'):
                self._certificate_operations(command)
            else:
                if command:
                    self._cli_print('unknown command: "/{0}"'.format(command))
                    self.help_print()
        else:
            self._cli_print('Unknown command: "{0}'.format(command))
            self.help_print()

    def _certificate_operations(self, command):
        self.logger.debug('CommandLineInterface._certificate_operations(): {0}'.format(command))

    def _config_operations(self, command):
        self.logger.debug('CommandLineInterface._config_operations(): {0}'.format(command))
        self._cli_print('server: {0}'.format(self.server), printreturn=False)
        self._cli_print('key: {0}'.format(self.key), printreturn=False)
        self._cli_print('status: {0}'.format(self.status), printreturn=False)

    def _exec_cmd(self, cmdinput):
        """ execute command """
        self.logger.debug('CommandLineInterface._exec_cmd(): {0}'.format(cmdinput))
        cmdinput = cmdinput.rstrip()
        # skip empty commands
        if len(cmdinput) <= 1:
            return

        if cmdinput.startswith("/"):
            cmdinput = cmdinput[1:]
        else:
            self._cli_print('Please enter a valid command!')
            self.help_print()
            return

        self._command_check(cmdinput)

    def _intro_print(self):
        """ print cli intro """
        self.logger.debug('CommandLineInterface._intro_print()')
        self._cli_print(CLI_INTRO.format(cliversion=VERSION))

    def _key_operations(self, command):
        """ key operations """
        self.logger.debug('CommandLineInterface._key_operations({0})'.format(command))

        try:
            (_key, command, argument) = command.split(' ', 2)
        except Exception:
            self._cli_print('incomplete key-operations command: "{0}"'.format(command))
            _key = None  # lgtm [py/unused-local-variable]
            command = None
            argument = None  # lgtm [py/unused-local-variable]

        if command and argument:
            key = KeyOperations(self.logger, self._cli_print)
            if command == 'generate':
                self.key = key.generate(argument)
            elif command == 'load':
                self.key = key.load(argument)
            else:
                self._cli_print('unknown key command: "{0}"'.format(command))

            if self.server:
                self.status = 'Configured'

    def _message_operations(self, command):
        """ message operations"""
        self.logger.debug('CommandLineInterface._message_operations()')

        try:
            (_key, command, argument) = command.split(' ', 2)
        except Exception:
            self._cli_print('incomplete message-operations command: "{0}"'.format(command))
            _key = None  # lgtm [py/unused-local-variable]
            command = None
            argument = None  # lgtm [py/unused-local-variable]

        if command and argument:
            message = MessageOperations(self.logger, self._cli_print)

            if command == 'sign':
                signed_message = message.sign(key=self.key, data=argument)
                self._cli_print(signed_message)
            elif command.startswith('send'):
                signed_message = message.sign(key=self.key, data=argument)
                message.send(server=self.server, message=signed_message)

    def _report_operations(self, command):
        """ report operations """
        self.logger.debug('CommandLineInterface._message_operations()')
        try:
            (_key, command, filename) = command.split(' ', 2)
        except Exception:
            self._cli_print('incomplete report-operations command: "{0}"'.format(command))
            command = None
            filename = None  # lgtm [py/unused-local-variable]

        if command and filename:
            try:
                (_filename, format_) = filename.lower().split('.', 2)
            except Exception:
                self._cli_print('incomplete filename: "{0}"'.format(command))
                format_ = None

            if format_ in ('csv', 'json'):
                self._report_generate(filename, format_, command)
            else:
                self._cli_print('Unknown report format "{0}". Must be either "csv" or "json"'.format(format))

    def _report_generate(self, filename, format_, command):
        """ generate report """
        self.logger.debug('CommandLineInterface._report_generate()')

        # process report request
        message = MessageOperations(self.logger, self._cli_print)
        signed_message = message.sign(key=self.key, type='report', data={'name': command, 'format': format_})
        response = message.send(server=self.server, message=signed_message)
        if response.status_code == 200:
            if format_ == 'csv':
                csv_dump(self.logger, filename, response.json())
            else:
                file_dump(self.logger, filename, json.dumps(response.json(), indent=4, sort_keys=True))
            self._cli_print('saving report to {0}'.format(filename))
        else:
            if 'message' in response.json():
                message = response.json()['message']
            elif 'detail' in response.json():
                message = response.json()['detail']
            else:
                message = None
            self._cli_print('ERROR: {0} - {1}'.format(response.status_code, message))

    def _prompt_get(self):
        """ get prompt """
        self.logger.debug('CommandLineInterface._prompt_get()')
        return '[{0}]:'.format(self.status)

    def _quit(self):
        """ quit (whatever) """
        self.logger.debug('CommandLineInterface.quit()')
        sys.exit(0)

    def _server_set(self, server):
        """ configure server """
        self.logger.debug('CommandLineInterface._server_set({0})'.format(server))

        (_command, url) = server.split(' ')
        if is_url(url):
            self.server = url
            if self.key:
                self.status = 'Configured'
            else:
                self.status = 'Key missing'
        else:
            self._cli_print('{0} is not a valid url'.format(url))

    def help_print(self):
        """ help screen """
        self.logger.debug('CommandLineInterface.help_print()')
        helper = """-------------------------------------------------------------------------------
/certificate search <parameter> <string> - search certificate for a certain parameter
/certificate revoke <identifier> - revoke certificate on given uuid
/report certificates <filename> - download certificate report in either csf or json format
/report accounts <filename> - download certificate report in either csf or json format
/config show - show configuration
/key generate <filename> - generate a new JWK pair
/key load <filename> - load exisitng private JWK from file
/quit /Q - quit

"""
        self._cli_print(helper, date_print=False)

    def start(self):
        """ start """
        self.logger.debug('CommandLineInterface.start()')
        self._intro_print()

        while True:
            cmd = input(self._prompt_get()).strip()
            self._exec_cmd(cmd)


if __name__ == "__main__":

    # start cli
    CLI = CommandLineInterface()
    CLI.start()
