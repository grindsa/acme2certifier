"""
Django settings for acme2certifier (pip / a2c-manage default).

Override via ACME2CERTIFIER_* env vars, or replace/symlink this module for
production DB credentials (see examples/django for a MySQL template).
"""

import os
import warnings

import django
from django.core.exceptions import ImproperlyConfigured
from acme2certifier.acme_srv.helpers.config import load_config  # noqa: E402
from acme2certifier.acme_srv.helpers.logging_utils import (  # noqa: E402
    apply_log_levels,
    config_debug_get,
    env_debug_get,
    logger_setup,
)
from acme2certifier.acme_srv.helpers.network import (  # noqa: E402
    configured_server_name_get,
    server_name_allowed_host,
)

_DEFAULT_BASE = "/var/www/acme2certifier"
BASE_DIR = os.environ.get(
    "ACME2CERTIFIER_BASE_DIR",
    _DEFAULT_BASE if os.path.isdir(_DEFAULT_BASE) else os.getcwd(),
)

SECRET_KEY = os.environ.get(
    "ACME2CERTIFIER_SECRET_KEY",
    "django-insecure-change-me-run-a2c-django-secret-keygen",
)

DEBUG = env_debug_get()

ALLOWED_HOSTS = [
    h.strip()
    for h in os.environ.get("ACME2CERTIFIER_ALLOWED_HOSTS", "127.0.0.1,*").split(",")
    if h.strip()
]

if "*" in ALLOWED_HOSTS and not DEBUG:
    warnings.warn(
        "ALLOWED_HOSTS contains '*'; Host header validation is disabled. "
        "Set ACME2CERTIFIER_ALLOWED_HOSTS to explicit hostnames for production.",
        UserWarning,
        stacklevel=1,
    )

apply_log_levels(False)
_cfg = load_config()
_host = server_name_allowed_host(configured_server_name_get(_cfg) or "")
if _host and _host not in ALLOWED_HOSTS:
    logger_setup(config_debug_get(_cfg)).info(
        "Adding %s to ALLOWED_HOSTS from acme_srv.cfg server_name", _host
    )
    ALLOWED_HOSTS.append(_host)

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "acme2certifier.django_app.apps.AcmeSrvConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    # ACME clients POST JWS-signed bodies (application/jose+json), not browser
    # forms; CSRF tokens are incompatible. Auth is JWS + account keys (RFC 8555).
    # 'django.middleware.csrf.CsrfViewMiddleware',
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "acme2certifier.django_project.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "acme2certifier.django_project.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.path.join(BASE_DIR, "db.sqlite3"),
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_L10N = True
USE_TZ = True

STATIC_URL = "/static/"

DEFAULT_AUTO_FIELD = "django.db.models.AutoField"
