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
        from tools.a2c_cli import CommandLineInterface
        self.a2ccli = CommandLineInterface(logger=self.logger)

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

if __name__ == '__main__':
    unittest.main()
