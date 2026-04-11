"""build script for acme2certifier"""

import pathlib
import typing as t
from setuptools import setup
import shutil
from glob import glob
from acme_srv.version import __version__


def glob_files(pattern: str) -> t.List[str]:
    return [
        str(file_) for file_ in pathlib.Path(".").glob(pattern) if not file_.is_dir()
    ]


# Update nginx config files and copy them to /var/lib/acme2certifier/examples/nginx
def update_and_copy_nginx_configs():
    src_dir = pathlib.Path("examples/nginx")
    dst_dir = pathlib.Path("/var/lib/acme2certifier/examples/nginx")
    dst_dir.mkdir(parents=True, exist_ok=True)
    configs = [
        "nginx_acme_srv.conf",
        "nginx_acme_srv_ssl.conf",
        "supervisord.conf",
        "uwsgi.service",
        "acme2certifier.ini",
    ]
    for conf in configs:
        # Ensure only filename is used, preventing path traversal attacks
        safe_filename = pathlib.Path(conf).name
        src_file = src_dir / safe_filename
        dst_file = dst_dir / safe_filename
        if src_file.exists():
            content = src_file.read_text()
            content = content.replace(
                "/var/www/acme2certifier/volume/acme2certifier_cert.pem",
                "/etc/ssl/certs/acme2certifier_cert.pem",
            )
            content = content.replace(
                "/var/www/acme2certifier/volume/acme2certifier_key.pem",
                "/etc/ssl/private/acme2certifier_key.pem",
            )
            content = content.replace(
                "/var/www/acme2certifier", "/var/lib/acme2certifier"
            )
            content = content.replace("/opt/acme2certifier", "/var/lib/acme2certifier")
            content = content.replace(
                "/run/uwsgi/acme.sock", "/var/lib/acme2certifier/acme.sock"
            )
            content = content.replace(
                "uid = nginx", "uid = www-data\nplugins = python3"
            )
            content = content.replace("chown-socket = nginx", "chown-socket = www-data")
            dst_file.write_text(content)
        else:
            print(f"Warning: {src_file} not found.")


update_and_copy_nginx_configs()
setup(
    name="acme2certifier",
    version=__version__,
    description="ACMEv2 server",
    url="https://github.com/grindsa/acme2certifier",
    author="grindsa",
    author_email="grindelsack@gmail.com",
    license="GPL",
    include_package_data=True,
    data_files=[
        ("/usr/share/doc/acme2certifier/", glob_files("docs/*")),
        (
            "/usr/share/doc/acme2certifier/architecture",
            glob_files("docs/architecture/*"),
        ),
        ("/var/lib/acme2certifier/acme_srv/", glob_files("acme_srv/*.py")),
        (
            "/var/lib/acme2certifier/acme_srv/helpers",
            glob_files("acme_srv/helpers/*.py"),
        ),
        (
            "/var/lib/acme2certifier/acme_srv/challenge_validators",
            glob_files("acme_srv/challenge_validators/*.py"),
        ),
        ("/var/lib/acme2certifier/examples", glob_files("examples/*.*")),
        (
            "/var/lib/acme2certifier/examples/ca_handler",
            glob_files("examples/ca_handler/*.py"),
        ),
        (
            "/var/lib/acme2certifier/examples/db_handler",
            glob_files("examples/db_handler/*.py"),
        ),
        (
            "/var/lib/acme2certifier/examples/eab_handler",
            glob_files("examples/eab_handler/*.py"),
        ),
        (
            "/var/lib/acme2certifier/examples/hooks",
            glob_files("examples/hooks/*.py"),
        ),
        ("/var/lib/acme2certifier/examples/django", glob_files("examples/django/*.py")),
        (
            "/var/lib/acme2certifier/examples/django/acme2certifier",
            glob_files("examples/django/acme2certifier/*.py"),
        ),
        (
            "/var/lib/acme2certifier/examples/django/acme_srv",
            glob_files("examples/django/acme_srv/*.py"),
        ),
        (
            "/var/lib/acme2certifier/examples/django/acme_srv/fixture",
            glob_files("examples/django/acme_srv/fixture/*"),
        ),
        (
            "/var/lib/acme2certifier/examples/django/acme_srv/migrations",
            glob_files("examples/django/acme_srv/migrations/*.py"),
        ),
        ("/var/lib/acme2certifier/examples/nginx", glob_files("examples/nginx/*")),
        ("/var/lib/acme2certifier/examples/trigger", glob_files("examples/trigger/*")),
        ("/var/lib/acme2certifier/tools", glob_files("tools/*.py")),
        ("/var/lib/acme2certifier/examples/Docker", glob_files("examples/Docker/*.*")),
        (
            "/var/lib/acme2certifier/examples/Docker/wsgi",
            glob_files("examples/Docker/wsgi/*"),
        ),
        (
            "/var/lib/acme2certifier/examples/Docker/django",
            glob_files("examples/Docker/django/*"),
        ),
    ],
    platforms="any",
    classifiers=[
        "Programming Language :: Python",
        "Development Status :: 4 - Beta",
        "Natural Language :: German",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    install_requires=[
        "setuptools",
        "jwcrypto",
        "cryptography",
        "pyOpenssl",
        "dnspython",
        "pytz",
        "configparser",
        "python-dateutil",
        "requests",
        "pysocks",
        "josepy",
        "acme",
        "xmltodict",
        "pyasn1",
        "pyasn1_modules",
        "requests_pkcs12",
        "pyyaml",
        "idna",
        "werkzeug>=3.0.6",  # not directly required, pinned by Snyk to avoid a vulnerability
    ],
    zip_safe=False,
    test_suite="test",
)
