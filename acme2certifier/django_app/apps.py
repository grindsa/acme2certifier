"""Django AppConfig for acme2certifier."""

from django.apps import AppConfig


class AcmeSrvConfig(AppConfig):
    """ACME server Django application (label kept as acme_srv for DB/fixture compat)."""

    name = "acme2certifier.django_app"
    label = "acme_srv"
    verbose_name = "ACME Server"
