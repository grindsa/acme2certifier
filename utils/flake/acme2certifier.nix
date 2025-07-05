{ self, pkgs, ca_handler, config }: let

  pythonPackages = pkgs.python313Packages;

in pythonPackages.buildPythonPackage {
  pname = "acme2certifier";
  version = "0.37.1";
  src = self;

  ca_handler = "acme_ca_handler.py";

  installPhase = let
    srvConfig = (pkgs.formats.ini{}).generate "acme_srv.cfg" config;
  in /* bash */ ''
    mkdir -p $out/examples
    cp examples/acme2certifier_wsgi.py $out/acme2certifier_wsgi.py
    cp examples/ca_handler/${ca_handler} $out/ca_handler.py

    cp -R examples/eab_handler/ $out/examples/eab_handler
    cp -R examples/hooks/ $out/examples/hooks
    cp -R examples/nginx/ $out/examples/nginx
    #cp examples/acme_srv.cfg $out/examples
    cp -R acme_srv/ $out/acme_srv
    cp -R tools/ $out/tools
    cp examples/db_handler/wsgi_handler.py $out/acme_srv/db_handler.py

    cp ${srvConfig} $out/acme_srv/acme_srv.cfg
  '';

  dependencies = with pythonPackages; [
    setuptools
    jwcrypto
    cryptography
    pyopenssl
    dnspython
    # certsrv[ntlm]
    pytz
    configparser
    python-dateutil
    requests
    pysocks
    josepy
    acme
    xmltodict
    pyasn1
    pyasn1-modules
    requests-pkcs12
    requests-gssapi
    gssapi
    pyyaml
    idna
    werkzeug
  ];

  runtimeInputs = [
    pkgs.krb5
  ];
}
