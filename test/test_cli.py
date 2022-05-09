#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for account.py """
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import importlib
import configparser
import sys
import datetime
from unittest.mock import patch, MagicMock, Mock

sys.path.insert(0, '.')
sys.path.insert(1, '..')

class FakeDBStore(object):
    """ face DBStore class needed for mocking """
    # pylint: disable=W0107, R0903
    pass

class TestACMEHandler(unittest.TestCase):
    """ test class for ACMEHandler """
    acme = None
    def setUp(self):
        """ setup unittest """
        import logging
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        from tools.a2c_cli import CommandLineInterface, KeyOperations, is_url
        self.a2ccli = CommandLineInterface(logger=self.logger)
        self.keyops = KeyOperations(logger=self.logger)
        self.is_url = is_url

    def test_001_always_pass(self):
        """ test successful tos check """
        self.assertTrue('foo')

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    def test_002_help_print(self, mock_cliprint):
        """ test print help """
        self.a2ccli.help_print()
        self.assertTrue(mock_cliprint.called)

    def test_003_prompt_get(self):
        """ test _prompt_get default status """
        self.assertEqual('[server missing]:', self.a2ccli._prompt_get())

    def test_004_prompt_get(self):
        """ test _prompt_get changed status  """
        self.a2ccli.status = 'status'
        self.assertEqual('[status]:', self.a2ccli._prompt_get())

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    def test_005_intro_print(self, mock_cliprint):
        """ test print help """
        self.a2ccli._intro_print()
        self.assertTrue(mock_cliprint.called)

    @patch('tools.a2c_cli.CommandLineInterface._command_check')
    @patch('tools.a2c_cli.CommandLineInterface.help_print')
    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    def test_006_exec_cmd(self, mock_cliprint, mock_help_print, mock_cmdchk):
        """ test exec_cmd correct command """
        cmdinput = '/foo'
        self.a2ccli._exec_cmd(cmdinput)
        self.assertFalse(mock_cliprint.called)
        self.assertFalse(mock_help_print.called)
        self.assertTrue(mock_cmdchk.called)

    @patch('tools.a2c_cli.CommandLineInterface._command_check')
    @patch('tools.a2c_cli.CommandLineInterface.help_print')
    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    def test_007_exec_cmd(self, mock_cliprint, mock_help_print, mock_cmdchk):
        """ test exec_cmd command without leading slash """
        cmdinput = 'foo'
        self.a2ccli._exec_cmd(cmdinput)
        self.assertTrue(mock_cliprint.called)
        self.assertTrue(mock_help_print.called)
        self.assertFalse(mock_cmdchk.called)

    @patch('tools.a2c_cli.CommandLineInterface._command_check')
    @patch('tools.a2c_cli.CommandLineInterface.help_print')
    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    def test_008_exec_cmd(self, mock_cliprint, mock_help_print, mock_cmdchk):
        """ test exec_cmd command only one char """
        cmdinput = '1'
        self.a2ccli._exec_cmd(cmdinput)
        self.assertFalse(mock_cliprint.called)
        self.assertFalse(mock_help_print.called)
        self.assertFalse(mock_cmdchk.called)

    @patch('builtins.print')
    @patch('tools.a2c_cli.datetime')
    def test_009_cli_print(self, mock_datetime, mock_print):
        """ test _cli_print """
        mock_datetime.datetime.now.return_value.strftime.return_value = 'datetime'
        self.a2ccli._cli_print('foo')
        self.assertTrue(mock_print.called)

    @patch('builtins.print')
    @patch('tools.a2c_cli.datetime.datetime')
    def test_009_cli_print(self, mock_datetime, mock_print):
        """ test _cli_print without text """
        # mock_datetime.now.return_value.strftime.return_value = 'datetime'
        mock_datetime.datetime.now.return_value.strftime.return_value = 'datetime'
        self.a2ccli._cli_print(None)
        self.assertFalse(mock_print.called)
        # self.assertTrue(mock_datetime.called)

    @patch('builtins.print')
    @patch('tools.a2c_cli.datetime')
    def test_010_cli_print(self, mock_datetime, mock_print):
        """ test _cli_print """
        mock_datetime.datetime.now.return_value.strftime.return_value = 'datetime'
        self.a2ccli._cli_print('foo', date_print=False)
        self.assertTrue(mock_print.called)
        self.assertFalse(mock_datetime.called)

    @patch('tools.a2c_cli.CommandLineInterface.help_print')
    def test_011_command_check(self, mock_help_print):
        """ test _command check with help paramter """
        command = 'help'
        self.a2ccli._command_check(command)
        self.assertTrue(mock_help_print.called)

    @patch('tools.a2c_cli.CommandLineInterface.help_print')
    def test_011_command_check(self, mock_help_print):
        """ test _command check with help paramter """
        command = 'H'
        self.a2ccli._command_check(command)
        self.assertTrue(mock_help_print.called)

    @patch('tools.a2c_cli.CommandLineInterface._server_set')
    def test_012_command_check(self, mock_server_set):
        """ test __servr_set() """
        command = 'server foo'
        self.a2ccli._command_check(command)
        self.assertTrue(mock_server_set.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.CommandLineInterface.help_print')
    def test_011_command_check(self, mock_help_print, mock_cli_print):
        """ test _command check with unconfigured environement """
        command = '/foo'
        self.a2ccli._command_check(command)
        self.assertTrue(mock_cli_print.called)
        self.assertFalse(mock_help_print.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.CommandLineInterface.help_print')
    def test_012_command_check(self, mock_help_print, mock_cli_print):
        """ test _command check with unconfigured environement """
        self.a2ccli.status = 'configured'
        command = '/foo'
        self.a2ccli._command_check(command)
        self.assertTrue(mock_cli_print.called)
        self.assertTrue(mock_help_print.called)

    @patch('tools.a2c_cli.CommandLineInterface._key_operations')
    def test_013_command_check(self, mock_keyops):
        """ test _command check with key generator """
        command = 'key foo'
        self.a2ccli._command_check(command)
        self.assertTrue(mock_keyops.called)

    @patch('tools.a2c_cli.is_url')
    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    def test_014_server_set(self, mock_cli_print, mock_is_url):
        """ test _server_set all good """
        command = 'server foo'
        mock_is_url.return_value = True
        self.a2ccli._server_set(command)
        self.assertEqual(self.a2ccli.server, 'foo')
        self.assertEqual(self.a2ccli.status, 'key missing')
        self.assertFalse(mock_cli_print.called)


    @patch('tools.a2c_cli.is_url')
    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    def test_015_server_set(self, mock_cli_print, mock_is_url):
        """ test _server_set all good """
        command = 'server foo'
        mock_is_url.return_value = True
        self.a2cclie.key = 'key'
        self.a2ccli._server_set(command)
        self.assertEqual(self.a2ccli.server, 'foo')
        self.assertEqual(self.a2ccli.status, 'configured')
        self.assertFalse(mock_cli_print.called)


    @patch('tools.a2c_cli.is_url')
    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    def test_015_server_set(self, mock_cli_print, mock_is_url):
        """ test _server_set all wrong url specified """
        command = 'server foo'
        mock_is_url.return_value = False
        self.a2ccli._server_set(command)
        self.assertFalse(self.a2ccli.server)
        self.assertEqual(self.a2ccli.status, 'server missing')
        self.assertTrue(mock_cli_print.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.KeyOperations.generate')
    @patch('tools.a2c_cli.KeyOperations.load')
    def test_016_key_operations(self, mock_load, mock_gen, mock_print):
        """ test key operations generate command """
        command = 'key generate foo'
        self.a2ccli._key_operations(command)
        self.assertTrue(mock_gen.called)
        self.assertFalse(mock_load.called)
        self.assertFalse(mock_print.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.KeyOperations.generate')
    @patch('tools.a2c_cli.KeyOperations.load')
    def test_017_key_operations(self, mock_load, mock_gen, mock_print):
        """ test key operations load command """
        command = 'key load foo'
        self.a2ccli._key_operations(command)
        self.assertFalse(mock_gen.called)
        self.assertTrue(mock_load.called)
        self.assertFalse(mock_print.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.KeyOperations.generate')
    @patch('tools.a2c_cli.KeyOperations.load')
    def test_016_key_operations(self, mock_load, mock_gen, mock_print):
        """ test key operations unknown command """
        command = 'key bar foo'
        self.a2ccli._key_operations(command)
        self.assertFalse(mock_gen.called)
        self.assertFalse(mock_load.called)
        self.assertTrue(mock_print.called)

    @patch('tools.a2c_cli.CommandLineInterface._cli_print')
    @patch('tools.a2c_cli.KeyOperations.generate')
    @patch('tools.a2c_cli.KeyOperations.load')
    def test_017_key_operations(self, mock_load, mock_gen, mock_print):
        """ test key operations incomplete command """
        command = 'key foo'
        self.a2ccli._key_operations(command)
        self.assertFalse(mock_gen.called)
        self.assertFalse(mock_load.called)
        self.assertTrue(mock_print.called)

    @patch('jwcrypto.jwk.JWK.generate')
    @patch('tools.a2c_cli.file_dump')
    def test_018_key_generate(self, mock_fd, mock_jwk):
        """ test key generation  all ok """
        self.keyops.print = Mock()
        self.keyops.generate('file_name')
        self.assertTrue(mock_jwk.called)
        self.assertTrue(mock_fd.called)

    @patch('jwcrypto.jwk.JWK.generate')
    @patch('tools.a2c_cli.file_dump')
    def test_019_key_generate(self, mock_fd, mock_jwk):
        """ test key generation  exception during filedump """
        mock_fd.side_effect = Exception('exc_fd')
        self.keyops.print = Mock()
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.keyops.generate('file_name')
        self.assertIn('ERROR:test_a2c:KeyOperations.generate() failed with err: exc_fd', lcm.output)
        self.assertTrue(mock_jwk.called)
        self.assertTrue(mock_fd.called)

    def test_020_isurl(self):
        """ test is_url """
        url = 'http://foo.bar'
        self.assertTrue(self.is_url(url))

    def test_021_isurl(self):
        """ test is_url """
        url = 'https://foo.bar'
        self.assertTrue(self.is_url(url))

    def test_022_isurl(self):
        """ test is_url """
        url = 'https://foo.bar/foo'
        self.assertTrue(self.is_url(url))

    def test_023_isurl(self):
        """ test is_url """
        url = 'https://foo.bar:80/foo'
        self.assertTrue(self.is_url(url))

    def test_024_isurl(self):
        """ test is_url """
        url = 'foo.bar'
        self.assertFalse(self.is_url(url))

if __name__ == '__main__':
    unittest.main()
