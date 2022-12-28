
# Disable automatic requires/provides processing
AutoReqProv: no

%global         projname        acme2certifier
%global         __python        %{__python3}
%global         dest_dir        /opt
%{!?_unitdir: %global _unitdir /usr/lib/systemd/system}

Summary:        library implementing ACME server functionality
Name:           acme2certifier

%define         ghowner   		grindsa

Version:        __version__
Release:        1.0
License:        GPL3; @grindsa@github
URL:            https://github.com/grindsa/acme2certifier
Requires:       nginx
# EPEL repo required
Requires:       policycoreutils-python-utils
Requires:       uwsgi-plugin-python3
Requires:       python3-uwsgidecorators
Requires:       tar
Requires:       python3-dateutil
Requires:       python3-pytz
Requires:       python3-setuptools
Requires:       python3-jwcrypto
Requires:       python3-cryptography
Requires:       python3-pyOpenSSL
Requires:       python3-dns
# Requires:       python-certsrv
Requires:       python3-configargparse
Requires:       python3-dateutil
Requires:       python3-requests
Requires:       python3-pysocks
Requires:       python3-josepy
Requires:       python3-acme
Requires:       python3-impacket
Requires:       python3-xmltodict
Requires:       python3-pyasn1
Requires:       python3-pyasn1-modules
Requires(post): policycoreutils

BuildArch:		noarch


Source0:        %{name}-%{version}.tar.gz

%description
acme2certifier is development project to create an ACME protocol proxy. Main intention is to provide ACME services on CA servers which do not support this protocol yet. It consists of two libraries:

- acme_srv/*.py - a bunch of classes implementing ACME server functionality based on rfc8555
- ca_handler.py - interface towards CA server. The intention of this library is to be
  modular that an adaption to other CA servers should be straight forward. As of
  today the following handlers are available:

  - Openssl
  - NetGuard Certificate Manager/Insta Certifier
  - NetGuard Certificate Lifecycle Manager
  - Generic EST protocol handler
  - Generic CMPv2 protocol handler
  - Microsoft Certificate Enrollment Web Services
  - Microsoft Windows Client Certificate Enrollment Protocol (MS-WCCE) via RPC/DCOM
  - Generic ACME protocol handler supporting Letsencrypt, BuyPass.com and ZeroSSL
  - XCA
  - acme2dfn (external; ACME proxy for the German research network's SOAP API)

For more up-to-date information and further documentation, please visit the project's
home page at: https://github.com/grindsa/acme2certifier

Remember to:
  - enable acme2certifer service
	  sudo systemctl enable acme2certifier.service
	  sudo systemctl start acme2certifier.service
  - active acme2certifier in your nginx configuration
	  cp /opt/acme2certifer/examples/nginx/nginx_acme_srv[_ssl].conf /etc/nginx/conf.d
  - enable and start nginx service
	  sudo systemctl enable nginx.service
	  sudo systemctl start nginx.service

%prep
%autosetup -p1 -n %{name}-%{?ghsha}%{?!ghsha:%{version}} -N

%build
# nothing to build


%install
# Main
%{__mkdir_p} \
    %{buildroot}%{_datadir} \
    %{buildroot}%{_unitdir} \
    %{buildroot}%{dest_dir}/%{name}/examples \
	%{buildroot}%{_docdir}/%{projname} \
    #\
    #%{buildroot}%{_sysconfdir}/httpd/conf.d \

# %{__cp} -a . %{buildroot}%{dest_dir}/%{projname}
%{__cp} -a acme_srv tools %{buildroot}%{dest_dir}/%{projname}
%{__cp} -a examples/ca_handler examples/db_handler examples/django examples/eab_handler examples/hooks examples/trigger examples/nginx %{buildroot}%{dest_dir}/%{projname}/examples

%{__chmod} -R go-w %{buildroot}%{dest_dir}/%{projname}

%{__cp} -a \
    examples/acme_srv.cfg \
    %{buildroot}%{dest_dir}/%{projname}/acme_srv/acme_srv.cfg

%{__cp} -a \
    examples/db_handler/wsgi_handler.py \
    %{buildroot}%{dest_dir}/%{projname}/acme_srv/db_handler.py

%{__cp} -a \
    examples/acme2certifier_wsgi.py \
    %{buildroot}%{dest_dir}/%{projname}/

## Modify acme2certifier.ini for Redhat/Centos and derivations
%{__sed} '
$a\
plugins = python3
' \
  examples/nginx/acme2certifier.ini > \
  %{buildroot}%{dest_dir}/%{projname}/acme2certifier.ini

## Configure and enable uWSGI service
%{__sed} '
/^User/i\
WorkingDirectory=%{dest_dir}
' \
    examples/nginx/uwsgi.service > \
    %{buildroot}%{_unitdir}/acme2certifier.service    # ugh


%clean
%{__chmod} -R 777 $RPM_BUILD_ROOT
%{__rm} -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%license LICENSE
%doc *.md requirements.txt docs/*.md
%attr(0755,nginx,-)%{dest_dir}/%{projname}/
%{_unitdir}/acme2certifier.service

%changelog

%post
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
checkmodule -M -m -o /tmp/acme2certifier.mod /tmp/acme2certifier.te
semodule_package -o /tmp/acme2certifier.pp -m /tmp/acme2certifier.mod
semodule -i /tmp/acme2certifier.pp
rm /tmp/acme2certifier.pp
rm /tmp/acme2certifier.mod
rm /tmp/acme2certifier.te
