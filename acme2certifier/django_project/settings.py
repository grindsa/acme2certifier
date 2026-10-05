"""
Django settings for acme2certifier (pip / a2c-manage default).

Override via ACME2CERTIFIER_* env vars (including ACME2CERTIFIER_DATABASE_URL),
or replace/symlink this module for production DB credentials (see
examples/django for a MySQL template).
"""

import warnings

from django.core.exceptions import ImproperlyConfigured
from acme2certifier.acme_srv.helpers.config import load_config  # noqa: E402
from acme2certifier.acme_srv.helpers.logging_utils import (  # noqa: E402
    apply_log_levels,
    config_debug_get,
    logger_setup,
)
from acme2certifier.acme_srv.helpers.network import (  # noqa: E402
    configured_server_name_get,
    server_name_allowed_host,
)
from acme2certifier.django_project.settings_env import (  # noqa: E402
    INSECURE_SECRET_KEY,
    load_settings_env,
)

_cfg_env = load_settings_env()
BASE_DIR = _cfg_env["BASE_DIR"]
SECRET_KEY = _cfg_env["SECRET_KEY"]
DEBUG = _cfg_env["DEBUG"]
ALLOWED_HOSTS = _cfg_env["ALLOWED_HOSTS"]
DATABASES = _cfg_env["DATABASES"]

if SECRET_KEY == INSECURE_SECRET_KEY and not DEBUG:
    raise ImproperlyConfigured(
        "ACME2CERTIFIER_SECRET_KEY is unset or still the insecure default. "
        "Set ACME2CERTIFIER_SECRET_KEY (e.g. via a2c-django-secret-keygen), "
        "or set ACME2CERTIFIER_DEBUG=1 for local development only."
    )

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
