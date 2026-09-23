"""Session fixtures for acme2certifier unit tests."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CA_DIR = Path(__file__).resolve().parent / "ca"
_BOOTSTRAP_MARKER = _CA_DIR / "sub-ca-key.pem"
_MAKE_TEST_CAS = _REPO_ROOT / "tools" / "make_test_cas.sh"


@pytest.fixture(scope="session", autouse=True)
def openssl_test_ca() -> None:
    """Ensure openssl lab CA PEMs exist under test/ca (generate-if-missing)."""
    if _BOOTSTRAP_MARKER.is_file():
        return
    if not _MAKE_TEST_CAS.is_file():
        pytest.fail(f"missing {_MAKE_TEST_CAS}")
    try:
        subprocess.run(
            [str(_MAKE_TEST_CAS), "bootstrap", "-c", str(_CA_DIR), "-o", str(_CA_DIR)],
            check=True,
            cwd=str(_REPO_ROOT),
            env={**os.environ},
        )
    except FileNotFoundError as exc:
        pytest.fail(f"openssl/bootstrap failed: {exc}")
    except subprocess.CalledProcessError as exc:
        pytest.fail(f"tools/make_test_cas.sh bootstrap failed with exit {exc.returncode}")
    if not _BOOTSTRAP_MARKER.is_file():
        pytest.fail(f"bootstrap did not create {_BOOTSTRAP_MARKER}")
