# -*- coding: utf-8 -*-
"""Shared Django settings bootstrap for tools, WSGI, and the Django DB handler."""

from __future__ import annotations

import os
import sys
from typing import Optional

DEFAULT_DJANGO_SETTINGS = "acme2certifier.django_project.settings"


def configure_django_settings_module(
    settings_module: str = DEFAULT_DJANGO_SETTINGS,
) -> str:
    """Set ``DJANGO_SETTINGS_MODULE`` when unset and return the active value."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", settings_module)
    return os.environ["DJANGO_SETTINGS_MODULE"]


def prepend_sys_path_if_dir(path: Optional[str]) -> None:
    """Prepend an existing directory to ``sys.path`` once."""
    if not path or not os.path.isdir(path) or path in sys.path:
        return
    sys.path.insert(0, path)
