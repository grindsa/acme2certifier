FROM ubuntu:22.04
LABEL maintainer="grindelsack@gmail.com"

ENV APACHE_RUN_USER www-data
ENV APACHE_RUN_GROUP www-data
ENV APACHE_LOG_DIR /var/log/apache2

RUN apt-get update  && \
    DEBIAN_FRONTEND="noninteractive" apt-get -y install --no-install-recommends tzdata && \
    DEBIAN_FRONTEND="noninteractive" apt-get install --no-install-recommends -y \
    python3-pip \
    apache2 \
    apache2-data \
    libapache2-mod-wsgi-py3 \
    curl \
    krb5-user \
    libgssapi-krb5-2 \
    libkrb5-3 \
    python3-gssapi \
    && rm -rf /var/lib/apt/lists/* &&\
    mkdir -p /var/www/acme2certifier/volume && \
    mkdir -p /var/www/acme2certifier/examples /var/www/acme2certifier/examples/

COPY ./ /var/www/acme2certifier/

# configure acme2certifier
RUN pip3 install -r /var/www/acme2certifier/requirements.txt  && \
    cp /var/www/acme2certifier/examples/apache2/apache_wsgi.conf /etc/apache2/sites-enabled/acme2certifier.conf  && \
    cp /var/www/acme2certifier/examples/acme2certifier_wsgi.py /var/www/acme2certifier/acme2certifier_wsgi.py  && \
    cp /var/www/acme2certifier/examples/db_handler/wsgi_handler.py /var/www/acme2certifier/acme_srv/db_handler.py  && \
    rm /var/www/acme2certifier/CHANGES.md /var/www/acme2certifier/README.md /var/www/acme2certifier/SECURITY.md /var/www/acme2certifier/setup.py /var/www/acme2certifier/requirements.txt && \
    cp /var/www/acme2certifier/examples/Docker/apache2/wsgi/docker-entrypoint.sh /docker-entrypoint.sh && \
    rm -rf /var/www/acme2certifier/examples/Docker /var/www/acme2certifier/examples/django /var/www/acme2certifier/examples/db_handler /var/www/acme2certifier/examples/nginx /var/www/acme2certifier/examples/acme_srv.db.example /var/www/acme2certifier/examples/acme2certifier_wsgi.py  && \
    chown -R www-data:www-data /var/www/acme2certifier/ && \
    sed -i "s/default = default_sect/\default = default_sect\nlegacy = legacy_sect/g" /etc/ssl/openssl.cnf && \
    sed -i "s/\[default_sect\]/\[default_sect\]\nactivate = 1\n\[legacy_sect\]\nactivate = 1/g" /etc/ssl/openssl.cnf && \
    sed -i "s/\${APACHE_LOG_DIR}\/error.log/\/dev\/stderr/g" /etc/apache2/apache2.conf && \
    a2enmod ssl && \
    rm /etc/apache2/sites-enabled/000-default.conf && \
    chmod a+rx /docker-entrypoint.sh

WORKDIR /var/www/acme2certifier/

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]

EXPOSE 80 443
