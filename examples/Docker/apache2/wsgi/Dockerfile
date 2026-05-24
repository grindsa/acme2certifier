FROM ubuntu:24.04
LABEL maintainer="grindelsack@gmail.com"

ENV APACHE_RUN_USER=www-data
ENV APACHE_RUN_GROUP=www-data
ENV APACHE_LOG_DIR=/var/log/apache2

COPY ./*.deb /tmp/
COPY ./examples/Docker/apache2/wsgi/docker-entrypoint.sh /docker-entrypoint.sh

RUN apt-get update  && \
    DEBIAN_FRONTEND="noninteractive" apt-get -y install --no-install-recommends tzdata && \
    DEBIAN_FRONTEND="noninteractive" apt-get install --no-install-recommends -y \
    apache2 \
    apache2-data \
    curl \
    krb5-user \
    libapache2-mod-wsgi-py3 \
    libgssapi-krb5-2 \
    libkrb5-3 \
    python3-gssapi \
    python3-impacket \
    python3-pip && \
    pip3 install requests-pkcs12 --break-system-packages && \
    rm -rf /usr/lib/python3/dist-packages/impacket/examples && \
    rm -rf /usr/share/doc/python3-impacke/examples && \
    rm -rf /usr/share/impacket/script* && \
    rm -rf /usr/bin/impacket-* && \
    DEBIAN_FRONTEND="noninteractive" apt-get install --no-install-recommends -y /tmp/acme2*.deb && \
    apt-get clean &&  \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* /tmp/* && \
    mkdir -p /var/www/acme2certifier/volume && \
    mkdir -p /var/www/acme2certifier/examples /var/www/acme2certifier/examples/ && \
    cp /var/www/acme2certifier/examples/apache2/apache_wsgi.conf /etc/apache2/sites-enabled/acme2certifier.conf  && \
    cp /var/www/acme2certifier/examples/db_handler/wsgi_handler.py /var/www/acme2certifier/acme_srv/db_handler.py  && \
    rm -rf /var/www/acme2certifier/examples/Docker && \
    rm -rf /var/www/acme2certifier/examples/django && \
    rm -rf /var/www/acme2certifier/examples/db_handler && \
    rm -rf /var/www/acme2certifier/examples/nginx && \
    rm -f /var/www/acme2certifier/acme_srv/acme_srv.cfg && \
    chown -R www-data:www-data /var/www/acme2certifier/ && \
    sed -i "s/default = default_sect/\default = default_sect\nlegacy = legacy_sect/g" /etc/ssl/openssl.cnf && \
    sed -i "s/\[default_sect\]/\[default_sect\]\nactivate = 1\n\[legacy_sect\]\nactivate = 1/g" /etc/ssl/openssl.cnf && \
    sed -i "s/\${APACHE_LOG_DIR}\/error.log/\/dev\/stderr/g" /etc/apache2/apache2.conf && \
    a2enmod ssl && \
    rm /etc/apache2/sites-enabled/000-default.conf && \
    chmod a+rx /docker-entrypoint.sh  # NOSONAR
WORKDIR /var/www/acme2certifier/

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]

EXPOSE 80 443
