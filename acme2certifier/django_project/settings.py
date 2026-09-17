"""
Django settings for acme2certifier (pip / a2c-manage default).

Override via ACME2CERTIFIER_* env vars, or replace/symlink this module for
production DB credentials (see examples/django for a MySQL template).
"""

from pathlib import Path
import environ

_DEFAULT_BASE = Path("/var/www/acme2certifier")
BASE_DIR = Path(env("ACME2CERTIFIER_BASE_DIR", default=str(_DEFAULT_BASE if _DEFAULT_BASE.is_dir() else Path.cwd())))

env = environ.Env(
    ACME2CERTIFIER_DEBUG=(bool, False),
    ACME2CERTIFIER_ALLOWED_HOSTS=(list, ["127.0.0.1", "*"]),
)

SECRET_KEY = env(
    "ACME2CERTIFIER_SECRET_KEY",
    default="django-insecure-change-me-run-a2c-django-secret-keygen",
)

DEBUG = env("ACME2CERTIFIER_DEBUG")

ALLOWED_HOSTS = env("ACME2CERTIFIER_ALLOWED_HOSTS")

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
    "default": env.db(
        "ACME2CERTIFIER_DATABASE_URL",
        default=f"sqlite:///{BASE_DIR}/db.sqlite3",
    )
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
