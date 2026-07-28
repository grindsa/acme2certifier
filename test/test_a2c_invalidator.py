#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for a2c_invalidator.py"""

# pylint: disable=C0415
import sys
import unittest
from unittest.mock import MagicMock, patch


class TestA2CInvalidator(unittest.TestCase):
    """tests for a2c_invalidator"""

    def test_001_main_runs_housekeeping_tasks(self):
        """main() invalidates orders/auths and updates cert dates"""
        mock_hk_cm = MagicMock()
        mock_hk = MagicMock()
        mock_hk_cm.__enter__.return_value = mock_hk
        mock_hk_cm.__exit__.return_value = False

        with patch(
            "acme2certifier.tools.a2c_invalidator.logger_setup",
            return_value=MagicMock(),
        ), patch(
            "acme2certifier.tools.a2c_invalidator.uts_to_date_utc",
            return_value="2024-01-01-000000",
        ), patch(
            "acme2certifier.tools.a2c_invalidator.Housekeeping",
            return_value=mock_hk_cm,
        ), patch("acme2certifier.tools.a2c_invalidator.time.time", return_value=1):
            from acme2certifier.tools import a2c_invalidator

            a2c_invalidator.main()

        mock_hk.orders_invalidate.assert_called_once_with(
            report_format="csv", report_name="orders_invalidate_2024-01-01-000000"
        )
        mock_hk.authorizations_invalidate.assert_called_once_with(
            report_format="csv",
            report_name="authorization_expire_2024-01-01-000000",
        )
        mock_hk.certificate_dates_update.assert_called_once()

    def test_002_module_main_entrypoint(self):
        """``__main__`` guard calls main()"""
        import runpy

        sys.modules.pop("acme2certifier.tools.a2c_invalidator", None)
        mock_hk_cm = MagicMock()
        mock_hk_cm.__enter__.return_value = MagicMock()
        mock_hk_cm.__exit__.return_value = False
        with patch(
            "acme2certifier.acme_srv.helper.logger_setup", return_value=MagicMock()
        ), patch(
            "acme2certifier.acme_srv.helper.uts_to_date_utc",
            return_value="suffix",
        ), patch(
            "acme2certifier.acme_srv.housekeeping.Housekeeping",
            return_value=mock_hk_cm,
        ):
            runpy.run_module(
                "acme2certifier.tools.a2c_invalidator",
                run_name="__main__",
                alter_sys=True,
            )


if __name__ == "__main__":
    unittest.main()
