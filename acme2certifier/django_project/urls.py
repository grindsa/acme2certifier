"""acme2certifier URL Configuration"""

from django.urls import include, re_path
from django.contrib import admin
from django.views.generic import RedirectView
from acme2certifier.django_app import views
from acme2certifier.acme_srv.helper import load_config

CONFIG = load_config()

if "Directory" in CONFIG and "url_prefix" in CONFIG["Directory"]:
    PREFIX = CONFIG["Directory"]["url_prefix"] + "/"
    if PREFIX.startswith("/"):
        PREFIX = PREFIX.lstrip("/")
else:
    PREFIX = ""

urlpatterns = [
    re_path(r"^admin/", admin.site.urls),
    re_path(r"^$", RedirectView.as_view(url="/directory")),
    re_path(r"^directory$", views.directory, name="directory"),
    re_path(rf"^{PREFIX}get_servername$", views.servername_get, name="servername_get"),
    re_path(rf"^{PREFIX}housekeeping$", views.housekeeping, name="housekeeping"),
    re_path(rf"^{PREFIX}acme/", include("acme2certifier.django_app.urls")),
]

if getattr(views, "TRIGGER_ENDPOINT_ENABLED", False) is True:
    urlpatterns.append(re_path(rf"^{PREFIX}trigger$", views.trigger, name="trigger"))

if "CAhandler" in CONFIG and "acme_url" in CONFIG["CAhandler"]:
    urlpatterns.append(
        re_path(
            rf"^{PREFIX}.well-known/acme-challenge/",
            views.acmechallenge_serve,
            name="acmechallenge_serve",
        )
    )
