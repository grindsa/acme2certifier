"""
Django settings template (MySQL) for Docker / external DB installs.

Copy to a volume and symlink over acme2certifier.django_project.settings,
or set DJANGO_SETTINGS_MODULE to a customized module.

Packaged SQLite defaults: acme2certifier.django_project.settings
"""

import os

_DEFAULT_BASE = "/var/www/acme2certifier"
BASE_DIR = os.environ.get(
    "ACME2CERTIFIER_BASE_DIR",
    _DEFAULT_BASE if os.path.isdir(_DEFAULT_BASE) else os.getcwd(),
)

TBR = "TO BE REPLACED"

SECRET_KEY = TBR

DEBUG = False

ALLOWED_HOSTS = ["127.0.0.1"]

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
        "ENGINE": "django.db.backends.mysql",
        "NAME": "acme2certifier",
        "USER": "acme2certifier",
        "PASSWORD": TBR,
        "HOST": TBR,
        "OPTIONS": {
            "init_command": "SET sql_mode='STRICT_TRANS_TABLES', innodb_strict_mode=1",
            "charset": "utf8mb4",
            "use_unicode": True,
        },
    },
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
