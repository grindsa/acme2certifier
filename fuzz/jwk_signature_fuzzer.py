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
"""Fuzz JWK thumbprint and JWS signature verification helpers."""

import json
import logging
import sys

import atheris

with atheris.instrument_imports():
    from acme2certifier.acme_srv.helpers.crypto import (
        jwk_thumbprint_get,
        signature_check,
    )

_LOGGER = logging.getLogger("fuzz")
_LOGGER.addHandler(logging.NullHandler())
_LOGGER.setLevel(logging.CRITICAL)


def TestOneInput(data: bytes) -> None:
    """Fuzz jwk_thumbprint_get and signature_check."""
    fdp = atheris.FuzzedDataProvider(data)
    as_json = fdp.ConsumeBool()
    key_blob = fdp.ConsumeUnicodeNoSurrogates(max(1, fdp.remaining_bytes() // 2))
    message = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())

    # Thumbprint expects a dict; tolerate invalid JSON.
    try:
        pub_dict = json.loads(key_blob)
        if isinstance(pub_dict, dict):
            jwk_thumbprint_get(_LOGGER, pub_dict)
    except Exception:
        pass

    # signature_check: json_=True wants a JSON string; False wants a mapping.
    try:
        if as_json:
            signature_check(_LOGGER, message, key_blob, json_=True)
        else:
            try:
                pub_key = json.loads(key_blob)
            except Exception:
                pub_key = key_blob
            signature_check(_LOGGER, message, pub_key, json_=False)
    except Exception:
        pass


def main() -> None:
    """Entrypoint for Atheris / OSS-Fuzz."""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
