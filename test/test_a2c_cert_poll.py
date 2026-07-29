#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for a2c_cert_poll.py"""

# pylint: disable=C0415, W0212
import importlib
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


class TestA2CCertPoll(unittest.TestCase):
    """tests for a2c_cert_poll"""

    def test_001_main_polls_processing_certs(self):
        """main() searches processing certs and polls each"""
        mock_cert_cm = MagicMock()
        mock_cert = MagicMock()
        mock_cert_cm.__enter__.return_value = mock_cert
        mock_cert_cm.__exit__.return_value = False
        mock_cert.certlist_search.return_value = [
            {
                "name": "c1",
                "poll_identifier": "p1",
                "csr": "csr1",
                "order__name": "o1",
            },
            {
                "name": "c2",
                "poll_identifier": "p2",
                "csr": "csr2",
                "order__name": "o2",
            },
        ]

        with patch(
            "acme2certifier.tools.a2c_cert_poll.initialize"
        ) as mock_init, patch(
            "acme2certifier.tools.a2c_cert_poll.logger_setup"
        ) as mock_log, patch(
            "acme2certifier.tools.a2c_cert_poll.Certificate",
            return_value=mock_cert_cm,
        ):
            mock_log.return_value = MagicMock()
            from acme2certifier.tools import a2c_cert_poll

            a2c_cert_poll.main()

        mock_init.assert_called_once()
        mock_cert.certlist_search.assert_called_once_with(
            "order__status_id", 4, ("name", "poll_identifier", "csr", "order__name")
        )
        self.assertEqual(mock_cert.poll.call_count, 2)
        mock_cert.poll.assert_any_call("c1", "p1", "csr1", "o1")
        mock_cert.poll.assert_any_call("c2", "p2", "csr2", "o2")

    def test_002_main_empty_list(self):
        """main() handles empty cert list"""
        mock_cert_cm = MagicMock()
        mock_cert = MagicMock()
        mock_cert_cm.__enter__.return_value = mock_cert
        mock_cert_cm.__exit__.return_value = False
        mock_cert.certlist_search.return_value = []

        with patch("acme2certifier.tools.a2c_cert_poll.initialize"), patch(
            "acme2certifier.tools.a2c_cert_poll.logger_setup",
            return_value=MagicMock(),
        ), patch(
            "acme2certifier.tools.a2c_cert_poll.Certificate",
            return_value=mock_cert_cm,
        ):
            from acme2certifier.tools import a2c_cert_poll

            a2c_cert_poll.main()

        mock_cert.poll.assert_not_called()

    def test_003_module_main_entrypoint(self):
        """``__main__`` guard calls main()"""
        import runpy

        from acme2certifier.tools import a2c_cert_poll as mod

        path = Path(mod.__file__)
        sys.modules.pop("acme2certifier.tools.a2c_cert_poll", None)

        # importlib binds submodules on the parent package; required for
        # unittest.mock.patch on Python 3.10 (``__import__`` alone does not).
        db_handler = importlib.import_module("acme2certifier.acme_srv.db_handler")
        helper = importlib.import_module("acme2certifier.acme_srv.helper")
        certificate = importlib.import_module("acme2certifier.acme_srv.certificate")

        mock_cm = MagicMock()
        mock_cm.__enter__.return_value.certlist_search.return_value = []
        mock_cm.__exit__.return_value = False
        with patch.object(db_handler, "initialize"), patch.object(
            helper, "logger_setup", return_value=MagicMock()
        ), patch.object(certificate, "Certificate", return_value=mock_cm):
            runpy.run_path(str(path), run_name="__main__")


if __name__ == "__main__":
    unittest.main()
