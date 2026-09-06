# -*- coding: utf-8 -*-
"""unittests for a2c_harica_totp"""

# pylint: disable=C0415, W0212
import configparser
import runpy
import sys
import unittest
from io import StringIO
from unittest.mock import patch

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestA2cHaricaTotp(unittest.TestCase):
    """test class for a2c_harica_totp"""

    def test_001_seed_from_config_user(self):
        from acme2certifier.tools import a2c_harica_totp

        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "requester_email": "user@example.com",
            "requester_totp_seed": "JBSWY3DPEHPK3PXP",
            "approver_email": "approver@example.com",
            "approver_totp_seed": "KRSXG5CTMVRXEZLU",
        }
        with patch(
            "acme2certifier.tools.a2c_harica_totp.load_config", return_value=parser
        ):
            seed, email, error = a2c_harica_totp._seed_from_config(
                None, a2c_harica_totp.ROLE_USER
            )
        self.assertIsNone(error)
        self.assertEqual(seed, "JBSWY3DPEHPK3PXP")
        self.assertEqual(email, "user@example.com")

    def test_002_seed_from_config_approver(self):
        from acme2certifier.tools import a2c_harica_totp

        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "requester_email": "user@example.com",
            "requester_totp_seed": "JBSWY3DPEHPK3PXP",
            "approver_email": "approver@example.com",
            "approver_totp_seed": "KRSXG5CTMVRXEZLU",
        }
        with patch(
            "acme2certifier.tools.a2c_harica_totp.load_config", return_value=parser
        ):
            seed, email, error = a2c_harica_totp._seed_from_config(
                None, a2c_harica_totp.ROLE_APPROVER
            )
        self.assertIsNone(error)
        self.assertEqual(seed, "KRSXG5CTMVRXEZLU")
        self.assertEqual(email, "approver@example.com")

    def test_003_seed_missing(self):
        from acme2certifier.tools import a2c_harica_totp

        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"requester_email": "user@example.com"}
        with patch(
            "acme2certifier.tools.a2c_harica_totp.load_config", return_value=parser
        ):
            seed, email, error = a2c_harica_totp._seed_from_config(
                None, a2c_harica_totp.ROLE_USER
            )
        self.assertIsNone(seed)
        self.assertIn(
            "requester_totp_seed / requester_totp_seed_variable is missing", error
        )

    def test_003b_seed_from_variable(self):
        from acme2certifier.tools import a2c_harica_totp

        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "requester_email_variable": "HARICA_REQUESTER_EMAIL",
            "requester_totp_seed_variable": "HARICA_REQUESTER_TOTP",
        }
        with patch(
            "acme2certifier.tools.a2c_harica_totp.load_config", return_value=parser
        ):
            with patch.dict(
                "os.environ",
                {
                    "HARICA_REQUESTER_EMAIL": "env@example.com",
                    "HARICA_REQUESTER_TOTP": "JBSWY3DPEHPK3PXP",
                },
                clear=False,
            ):
                seed, email, error = a2c_harica_totp._seed_from_config(
                    None, a2c_harica_totp.ROLE_USER
                )
        self.assertIsNone(error)
        self.assertEqual(seed, "JBSWY3DPEHPK3PXP")
        self.assertEqual(email, "env@example.com")

    def test_003c_seed_direct_overwrites_variable(self):
        from acme2certifier.tools import a2c_harica_totp

        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "requester_totp_seed_variable": "HARICA_REQUESTER_TOTP",
            "requester_totp_seed": "KRSXG5CTMVRXEZLU",
            "requester_email": "cfg@example.com",
        }
        with patch(
            "acme2certifier.tools.a2c_harica_totp.load_config", return_value=parser
        ):
            with patch.dict(
                "os.environ",
                {"HARICA_REQUESTER_TOTP": "JBSWY3DPEHPK3PXP"},
                clear=False,
            ):
                seed, email, error = a2c_harica_totp._seed_from_config(
                    None, a2c_harica_totp.ROLE_USER
                )
        self.assertIsNone(error)
        self.assertEqual(seed, "KRSXG5CTMVRXEZLU")
        self.assertEqual(email, "cfg@example.com")

    def test_004_main_prints_code(self):
        from acme2certifier.tools import a2c_harica_totp

        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "requester_email": "user@example.com",
            "requester_totp_seed": "JBSWY3DPEHPK3PXP",
        }
        argv = ["a2c-harica-totp"]
        with patch.object(sys, "argv", argv):
            with patch(
                "acme2certifier.tools.a2c_harica_totp.load_config", return_value=parser
            ):
                with patch(
                    "acme2certifier.tools.a2c_harica_totp.totp_generate",
                    return_value="123456",
                ):
                    with patch("sys.stdout", new_callable=StringIO) as mock_out:
                        rc = a2c_harica_totp.main()
        self.assertEqual(rc, 0)
        self.assertEqual(mock_out.getvalue().strip(), "123456")

    def test_005_seed_no_cahandler_section(self):
        from acme2certifier.tools import a2c_harica_totp

        parser = configparser.ConfigParser()
        with patch(
            "acme2certifier.tools.a2c_harica_totp.load_config", return_value=parser
        ):
            seed, email, error = a2c_harica_totp._seed_from_config(
                None, a2c_harica_totp.ROLE_USER
            )
        self.assertIsNone(seed)
        self.assertIsNone(email)
        self.assertEqual("No [CAhandler] section in config file", error)

    def test_006_main_configfile_missing(self):
        from acme2certifier.tools import a2c_harica_totp

        argv = ["a2c-harica-totp", "-c", "/nonexistent/acme_srv.cfg"]
        with patch.object(sys, "argv", argv):
            with patch("sys.stderr", new_callable=StringIO) as mock_err:
                rc = a2c_harica_totp.main()
        self.assertEqual(rc, 1)
        self.assertIn("not found", mock_err.getvalue())

    def test_007_main_seed_error(self):
        from acme2certifier.tools import a2c_harica_totp

        argv = ["a2c-harica-totp"]
        with patch.object(sys, "argv", argv):
            with patch(
                "acme2certifier.tools.a2c_harica_totp._seed_from_config",
                return_value=(None, None, "seed boom"),
            ):
                with patch("sys.stderr", new_callable=StringIO) as mock_err:
                    rc = a2c_harica_totp.main()
        self.assertEqual(rc, 1)
        self.assertIn("seed boom", mock_err.getvalue())

    def test_008_main_totp_generate_raises(self):
        from acme2certifier.tools import a2c_harica_totp

        argv = ["a2c-harica-totp"]
        with patch.object(sys, "argv", argv):
            with patch(
                "acme2certifier.tools.a2c_harica_totp._seed_from_config",
                return_value=("JBSWY3DPEHPK3PXP", "user@example.com", None),
            ):
                with patch(
                    "acme2certifier.tools.a2c_harica_totp.totp_generate",
                    side_effect=ValueError("bad seed"),
                ):
                    with patch("sys.stderr", new_callable=StringIO) as mock_err:
                        rc = a2c_harica_totp.main()
        self.assertEqual(rc, 1)
        self.assertIn("Failed to generate TOTP", mock_err.getvalue())
        self.assertIn("bad seed", mock_err.getvalue())

    def test_009_main_verbose_prints_remaining(self):
        from acme2certifier.tools import a2c_harica_totp

        argv = ["a2c-harica-totp", "-v"]
        with patch.object(sys, "argv", argv):
            with patch(
                "acme2certifier.tools.a2c_harica_totp._seed_from_config",
                return_value=("JBSWY3DPEHPK3PXP", "user@example.com", None),
            ):
                with patch(
                    "acme2certifier.tools.a2c_harica_totp.totp_generate",
                    return_value="654321",
                ):
                    with patch(
                        "acme2certifier.tools.a2c_harica_totp.time.time",
                        return_value=10,
                    ):
                        with patch("sys.stdout", new_callable=StringIO) as mock_out:
                            with patch("sys.stderr", new_callable=StringIO) as mock_err:
                                rc = a2c_harica_totp.main()
        self.assertEqual(rc, 0)
        self.assertEqual(mock_out.getvalue().strip(), "654321")
        err = mock_err.getvalue()
        self.assertIn("role=user", err)
        self.assertIn("account=user@example.com", err)
        self.assertIn("remaining=20s", err)

    def test_010_module_main_exits(self):
        """cover if __name__ == '__main__' via runpy"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "requester_email": "user@example.com",
            "requester_totp_seed": "JBSWY3DPEHPK3PXP",
        }
        sys.modules.pop("acme2certifier.tools.a2c_harica_totp", None)
        with patch.object(sys, "argv", ["a2c-harica-totp"]):
            with patch(
                "acme2certifier.acme_srv.helper.load_config", return_value=parser
            ):
                with patch(
                    "acme2certifier.cahandlers.harica_ca_handler.totp_generate",
                    return_value="123456",
                ):
                    with patch("sys.exit") as mock_exit:
                        with patch("sys.stdout", new_callable=StringIO) as mock_out:
                            runpy.run_module(
                                "acme2certifier.tools.a2c_harica_totp",
                                run_name="__main__",
                                alter_sys=True,
                            )
        mock_exit.assert_called_once_with(0)
        self.assertEqual(mock_out.getvalue().strip(), "123456")


if __name__ == "__main__":
    unittest.main()
