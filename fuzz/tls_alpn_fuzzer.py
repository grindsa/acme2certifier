#!/usr/bin/python3
# Copyright 2026 grindsa
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Fuzz TLS-ALPN-01 ACME identifier extension checking."""

import logging
import sys

import atheris

with atheris.instrument_imports():
    from acme2certifier.acme_srv.helpers.certificates import (
        cert_acme_tls_alpn_extension_ok,
    )

_LOGGER = logging.getLogger("fuzz")
_LOGGER.addHandler(logging.NullHandler())
_LOGGER.setLevel(logging.CRITICAL)


def TestOneInput(data: bytes) -> None:
    """Fuzz cert_acme_tls_alpn_extension_ok."""
    fdp = atheris.FuzzedDataProvider(data)
    recode = fdp.ConsumeBool()
    digest = fdp.ConsumeUnicodeNoSurrogates(max(1, min(128, fdp.remaining_bytes() // 4)))
    certificate = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
    try:
        cert_acme_tls_alpn_extension_ok(_LOGGER, certificate, digest, recode=recode)
    except Exception:
        pass


def main() -> None:
    """Entrypoint for Atheris / OSS-Fuzz."""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
