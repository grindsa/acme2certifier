"""build script for acme2certifier"""

import pathlib

from setuptools import setup
from glob import glob
from acme_srv.version import __version__

def glob_files(pattern: str) -> t.List[str]:
    """
    like :func:`glob.glob()` but retrieve
    only non-directories.
    """
    return [
        file_
        for file_ in pathlib.Path(".").glob(pattern)
        if not file_.is_dir()
    ]


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
        ("/usr/share/doc/acme2certifier/architecture", glob_files("docs/architecture/*")),
        ("/var/lib/acme2certifier/acme_srv/", glob_files("acme_srv/*.py")),
        ("/var/lib/acme2certifier/examples", glob_files("examples/*.*")),
        (
            "/var/lib/acme2certifier/examples/ca_handler",
            glob_files("examples/ca_handler/*.py"),
        ),
        (
            "/var/lib/acme2certifier/examples/db_handler",
            glob_files("examples/db_handler/*.py"),
        ),
        ("/var/lib/acme2certifier/examples/django", glob_files("examples/django/*.py")),
        (
            "/var/lib/acme2certifier/examples/django/acme2certifier",
            glob_files("examples/django/acme2certifier/*.py"),
        ),
        (
            "/var/lib/acme2certifier/examples/django/acme",
            glob_files("examples/django/acme/*.py"),
        ),
        (
            "/var/lib/acme2certifier/examples/django/acme/fixture",
            glob_files("examples/django/acme/fixture/*"),
        ),
        (
            "/var/lib/acme2certifier/examples/django/acme/migrations",
            glob_files("examples/django/acme/migrations/*.py"),
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
    zip_safe=False,
    test_suite="test",
)
