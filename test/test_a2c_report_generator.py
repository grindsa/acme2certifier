#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for a2c_report_generator.py"""

# pylint: disable=C0415
import sys
import unittest
from unittest.mock import MagicMock, patch


class TestA2CReportGenerator(unittest.TestCase):
    """tests for a2c_report_generator"""

    def test_001_main_generates_reports(self):
        """main() invokes housekeeping report helpers"""
        mock_cm = MagicMock()
        mock_hk = MagicMock()
        mock_cm.__enter__.return_value = mock_hk
        mock_cm.__exit__.return_value = False

        with patch(
            "acme2certifier.tools.a2c_report_generator.logger_setup",
            return_value=MagicMock(),
        ), patch(
            "acme2certifier.tools.a2c_report_generator.uts_to_date_utc",
            return_value="2024-01-01-000000",
        ), patch(
            "acme2certifier.tools.a2c_report_generator.Housekeeping",
            return_value=mock_cm,
        ), patch(
            "acme2certifier.tools.a2c_report_generator.time.time", return_value=1
        ):
            from acme2certifier.tools import a2c_report_generator

            a2c_report_generator.main()

        mock_hk.certreport_get.assert_any_call(
            report_name="certificate_report_2024-01-01-000000", report_format="json"
        )
        mock_hk.certreport_get.assert_any_call(
            report_name="certificate_report_2024-01-01-000000"
        )
        mock_hk.accountreport_get.assert_any_call(
            report_name="account_report_2024-01-01-000000",
            report_format="json",
            nested=True,
        )
        mock_hk.accountreport_get.assert_any_call(
            report_name="account_report_2024-01-01-000000"
        )
        mock_hk.certificates_cleanup.assert_called_once()
        mock_hk.orders_invalidate.assert_called_once()
        mock_hk.authorizations_invalidate.assert_called_once()

    def test_002_module_main_entrypoint(self):
        """``__main__`` guard calls main()"""
        import runpy

        sys.modules.pop("acme2certifier.tools.a2c_report_generator", None)
        mock_cm = MagicMock()
        mock_cm.__enter__.return_value = MagicMock()
        mock_cm.__exit__.return_value = False
        with patch(
            "acme2certifier.acme_srv.helper.logger_setup", return_value=MagicMock()
        ), patch(
            "acme2certifier.acme_srv.helper.uts_to_date_utc", return_value="sfx"
        ), patch(
            "acme2certifier.acme_srv.housekeeping.Housekeeping",
            return_value=mock_cm,
        ):
            runpy.run_module(
                "acme2certifier.tools.a2c_report_generator",
                run_name="__main__",
                alter_sys=True,
            )


if __name__ == "__main__":
    unittest.main()
