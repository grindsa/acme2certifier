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
"""Fuzz PKCS#7 to PEM conversion."""

import logging
import sys

import atheris

with atheris.instrument_imports():
    from acme2certifier.acme_srv.helpers.certificates import pkcs7_to_pem

_LOGGER = logging.getLogger("fuzz")
_LOGGER.addHandler(logging.NullHandler())
_LOGGER.setLevel(logging.CRITICAL)


def TestOneInput(data: bytes) -> None:
    """Fuzz pkcs7_to_pem."""
    fdp = atheris.FuzzedDataProvider(data)
    # Prefer unicode for PEM strategies; also feed raw bytes as latin-1.
    if fdp.ConsumeBool():
        content = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
    else:
        content = fdp.ConsumeBytes(fdp.remaining_bytes()).decode("latin-1", errors="ignore")
    try:
        pkcs7_to_pem(_LOGGER, content)
    except Exception:
        pass


def main() -> None:
    """Entrypoint for Atheris / OSS-Fuzz."""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
