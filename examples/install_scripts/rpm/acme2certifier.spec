# Dual-EL noarch package: install under /opt (not %{python3_sitelib})
# so one RPM works on EL8 (Python 3.6) and EL9 (Python 3.9).
# Disable automatic requires/provides processing
AutoReqProv: no

%global         projname        acme2certifier
%global         __python        %{__python3}
%global         dest_dir        /opt
%global         app_root        %{dest_dir}/%{projname}
%{!?_unitdir: %global _unitdir /usr/lib/systemd/system}

Summary:        library implementing ACME server functionality
Name:           acme2certifier

%define         ghowner   		grindsa

Version:        __version__
Release:        1.0
License:        GPL3; @grindsa@github
URL:            https://github.com/grindsa/acme2certifier

# Core runtime (EPEL often required on EL8)
Requires:       python3
Requires:       tar
Requires:       python3-dateutil
Requires:       python3-pytz
Requires:       python3-setuptools
Requires:       python3-jwcrypto
Requires:       python3-cryptography
Requires:       python3-pyOpenSSL
Requires:       python3-dns
Requires:       python3-requests
Requires:       python3-requests-pkcs12
Requires:       python3-pysocks
Requires:       python3-josepy
Requires:       python3-acme
Requires:       python3-xmltodict
Requires:       python3-pyasn1
Requires:       python3-pyasn1-modules
Requires:       python3-pyyaml
Requires(post): policycoreutils
Requires:       policycoreutils-python-utils

# Web stack is operator-chosen (nginx+uWSGI or httpd+mod_wsgi)
Recommends:      nginx
Recommends:      uwsgi-plugin-python3
Recommends:      python3-uwsgidecorators
Recommends:      python3-dataclasses
Recommends:      krb5-workstation
Recommends:      krb5-libs

BuildArch:		noarch

Source0:        %{name}-%{version}.tar.gz

%description
acme2certifier is an ACME protocol proxy for CA servers that do not speak ACME natively.

This RPM installs:
  - the acme2certifier Python package under %{app_root}/acme2certifier
    (PYTHONPATH=%{app_root}; works on EL8 Python 3.6 and EL9 Python 3.9)
  - deploy files under %{app_root} (WSGI entry, share/, examples/, systemd unit)
  - console wrappers in %{_bindir} (a2c-*)

Web servers are not hard dependencies. For nginx+uWSGI:
  - cp %{app_root}/share/nginx/nginx_acme_srv[_ssl].conf /etc/nginx/conf.d/
  - systemctl enable --now acme2certifier nginx

Apache example vhosts are under %{app_root}/share/apache2/.

See https://github.com/grindsa/acme2certifier and docs/install_rpm.md.

%prep
%autosetup -p1 -n %{name}-%{?ghsha}%{?!ghsha:%{version}} -N

%build
# Pure-Python; no compile step. Files are staged under /opt for dual-EL.

%install
APP=%{buildroot}%{app_root}
%{__mkdir_p} \
    "$APP" \
    "$APP/examples" \
    %{buildroot}%{_unitdir} \
    %{buildroot}%{_bindir} \
    %{buildroot}%{_docdir}/%{projname}

# Importable package (parent of this dir is PYTHONPATH)
%{__cp} -a acme2certifier "$APP/"

# Operator-facing share/ (stable paths for docs/install scripts)
%{__rm} -rf "$APP/share"
%{__cp} -a acme2certifier/share "$APP/share"

%{__cp} -a examples/django examples/trigger "$APP/examples/"

# WSGI entry + default cfg at deploy root
%{__cp} -a acme2certifier/share/acme2certifier_wsgi.py "$APP/"
%{__cp} -a acme2certifier/share/acme_srv.cfg "$APP/acme_srv.cfg"
%{__sed} -i 's|/var/www/acme2certifier/acme_srv.db|%{app_root}/acme_srv.db|g' \
    "$APP/acme_srv.cfg"
%{__sed} -i 's|Writable by www-data after DEB install|Writable by nginx after RPM install|g' \
    "$APP/acme_srv.cfg"

# uWSGI ini: EL plugins + python-path for /opt layout
%{__cp} -a acme2certifier/share/nginx/acme2certifier.ini "$APP/acme2certifier.ini"
grep -q '^plugins' "$APP/acme2certifier.ini" || echo 'plugins = python3' >> "$APP/acme2certifier.ini"
if grep -q '^python-path' "$APP/acme2certifier.ini"; then
  %{__sed} -i 's|^python-path = .*|python-path = %{app_root}|' "$APP/acme2certifier.ini"
else
  echo 'python-path = %{app_root}' >> "$APP/acme2certifier.ini"
fi

# Apache examples: retarget paths; drop pip venv python-home
%{__sed} -i 's|/var/www/acme2certifier|%{app_root}|g' "$APP"/share/apache2/apache_*.conf
%{__sed} -i '/python-home=/d' "$APP"/share/apache2/apache_*.conf

# systemd unit for nginx/uWSGI path
cat > %{buildroot}%{_unitdir}/acme2certifier.service <<'UNIT'
[Unit]
Description=uWSGI instance to serve acme2certifier

[Service]
RuntimeDirectory=uwsgi
WorkingDirectory=/opt/acme2certifier
Environment=PYTHONPATH=/opt/acme2certifier
Environment=ACME_SRV_CONFIGFILE=/opt/acme2certifier/acme_srv.cfg
ExecStart=uwsgi --ini acme2certifier.ini
Restart=always
Type=notify
NotifyAccess=all
User=nginx

[Install]
WantedBy=multi-user.target
UNIT

%{__chmod} -R go-w "$APP"

# Console wrappers (set PYTHONPATH; do not rely on versioned sitelib)
install_wrapper() {
    name="$1"
    module="$2"
    cat > "%{buildroot}%{_bindir}/${name}" <<EOF
#!/bin/bash
export PYTHONPATH="/opt/acme2certifier\${PYTHONPATH:+:\${PYTHONPATH}}"
export ACME_SRV_CONFIGFILE="\${ACME_SRV_CONFIGFILE:-/opt/acme2certifier/acme_srv.cfg}"
exec /usr/bin/python3 -m ${module} "\$@"
EOF
    %{__chmod} 0755 "%{buildroot}%{_bindir}/${name}"
}

install_wrapper a2c-cli acme2certifier.tools.a2c_cli
install_wrapper a2c-db-update acme2certifier.tools.a2c_db_update
install_wrapper a2c-django-update acme2certifier.tools.a2c_django_update
install_wrapper a2c-django-secret-keygen acme2certifier.tools.a2c_django_secret_keygen
install_wrapper a2c-manage acme2certifier.tools.a2c_manage
install_wrapper a2c-eab-chk acme2certifier.tools.a2c_eab_chk
install_wrapper a2c-cert-poll acme2certifier.tools.a2c_cert_poll
install_wrapper a2c-cliuser-mgmt acme2certifier.tools.a2c_cliuser_mgmt
install_wrapper a2c-invalidator acme2certifier.tools.a2c_invalidator
install_wrapper a2c-report-generator acme2certifier.tools.a2c_report_generator
install_wrapper a2c-mswcce-connection-test acme2certifier.tools.a2c_mswcce_connection_test
install_wrapper a2c-wsgi2django acme2certifier.tools.a2c_wsgi2django

%clean
%{__chmod} -R 777 $RPM_BUILD_ROOT
%{__rm} -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%dir %attr(0755,nginx,nginx) %{app_root}
%config(noreplace) %attr(0644,nginx,nginx) %{app_root}/acme_srv.cfg
%attr(0755,nginx,nginx) %{app_root}/acme2certifier/
%attr(0755,nginx,nginx) %{app_root}/share/
%attr(0755,nginx,nginx) %{app_root}/examples/
%attr(0644,nginx,nginx) %{app_root}/acme2certifier_wsgi.py
%attr(0644,nginx,nginx) %{app_root}/acme2certifier.ini
%license LICENSE
%doc *.md requirements.txt docs/*.md
%{_unitdir}/acme2certifier.service
%attr(0755,root,root) %{_bindir}/a2c-cli
%attr(0755,root,root) %{_bindir}/a2c-db-update
%attr(0755,root,root) %{_bindir}/a2c-django-update
%attr(0755,root,root) %{_bindir}/a2c-django-secret-keygen
%attr(0755,root,root) %{_bindir}/a2c-manage
%attr(0755,root,root) %{_bindir}/a2c-eab-chk
%attr(0755,root,root) %{_bindir}/a2c-cert-poll
%attr(0755,root,root) %{_bindir}/a2c-cliuser-mgmt
%attr(0755,root,root) %{_bindir}/a2c-invalidator
%attr(0755,root,root) %{_bindir}/a2c-report-generator
%attr(0755,root,root) %{_bindir}/a2c-mswcce-connection-test
%attr(0755,root,root) %{_bindir}/a2c-wsgi2django

%changelog

%post
# SELinux: allow httpd_t (nginx) to talk to uWSGI socket (EL8 + EL9)
cat <<EOT > /tmp/acme2certifier.te
module acme2certifier 1.0;

require {
	type var_run_t;
	type initrc_t;
	type httpd_t;
	class sock_file write;
	class unix_stream_socket connectto;
}

#============= httpd_t ==============
allow httpd_t initrc_t:unix_stream_socket connectto;
allow httpd_t var_run_t:sock_file write;
EOT
if command -v checkmodule >/dev/null 2>&1 && command -v semodule_package >/dev/null 2>&1; then
    checkmodule -M -m -o /tmp/acme2certifier.mod /tmp/acme2certifier.te
    semodule_package -o /tmp/acme2certifier.pp -m /tmp/acme2certifier.mod
    semodule -i /tmp/acme2certifier.pp
    rm -f /tmp/acme2certifier.pp /tmp/acme2certifier.mod /tmp/acme2certifier.te
else
    rm -f /tmp/acme2certifier.te
    echo "acme2certifier: SELinux tools missing; skipped module install" >&2
fi

if id nginx >/dev/null 2>&1; then
    chown -R nginx:nginx /opt/acme2certifier 2>/dev/null || true
fi
