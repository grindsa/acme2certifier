"""
Django settings for acme2certifier (pip / a2c-manage default).

Override via ACME2CERTIFIER_* env vars, or replace/symlink this module for
production DB credentials (see examples/django for a MySQL template).
"""

import os
import warnings

from acme2certifier.tools.a2c_django_deploy_env import load_deploy_env
from django.core.exceptions import ImproperlyConfigured

load_deploy_env()

_DEFAULT_BASE = "/var/www/acme2certifier"
BASE_DIR = os.environ.get(
    "ACME2CERTIFIER_BASE_DIR",
    _DEFAULT_BASE if os.path.isdir(_DEFAULT_BASE) else os.getcwd(),
)

_INSECURE_SECRET_KEY = "django-insecure-change-me-run-a2c-django-secret-keygen"
SECRET_KEY = os.environ.get("ACME2CERTIFIER_SECRET_KEY", _INSECURE_SECRET_KEY)

DEBUG = os.environ.get("ACME2CERTIFIER_DEBUG", "0") in ("1", "true", "True")

if SECRET_KEY == _INSECURE_SECRET_KEY and not DEBUG:
    raise ImproperlyConfigured(
        "ACME2CERTIFIER_SECRET_KEY is unset or still the insecure default. "
        "Set ACME2CERTIFIER_SECRET_KEY (e.g. via a2c-django-secret-keygen), "
        "or set ACME2CERTIFIER_DEBUG=1 for local development only."
    )

_DEFAULT_ALLOWED_HOSTS = "127.0.0.1,*" if DEBUG else "127.0.0.1,localhost"
ALLOWED_HOSTS = [
    h.strip()
    for h in os.environ.get(
        "ACME2CERTIFIER_ALLOWED_HOSTS", _DEFAULT_ALLOWED_HOSTS
    ).split(",")
    if h.strip()
]

if "*" in ALLOWED_HOSTS and not DEBUG:
    warnings.warn(
        "ALLOWED_HOSTS contains '*'; Host header validation is disabled. "
        "Set ACME2CERTIFIER_ALLOWED_HOSTS to explicit hostnames for production.",
        UserWarning,
        stacklevel=1,
    )

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
