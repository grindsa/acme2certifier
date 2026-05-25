FROM ubuntu:26.04
LABEL maintainer="grindelsack@gmail.com"

COPY ./*.deb /tmp/
COPY ./examples/Docker/nginx/wsgi/docker-entrypoint.sh /docker-entrypoint.sh

RUN apt-get update  && \
    DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends tzdata && \
    DEBIAN_FRONTEND="noninteractive" apt-get install --no-install-recommends -y \
    curl \
    krb5-user \
    libgssapi-krb5-2 \
    libkrb5-3 \
    nginx \
    python3-gssapi \
    python3-impacket \
    python3-pip \
    python3-requests-gssapi \
    python3-yaml \
    supervisor \
    uwsgi \
    uwsgi-plugin-python3 && \
    DEBIAN_FRONTEND="noninteractive" apt-get install --no-install-recommends -y /tmp/acme2*.deb && \
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
    mkdir -p /run/uwsgi && \
    cp /var/www/acme2certifier/examples/db_handler/wsgi_handler.py /var/www/acme2certifier/acme_srv/db_handler.py && \
    cp /var/www/acme2certifier/examples/nginx/acme2certifier.ini /var/www/acme2certifier && \
    cp /var/www/acme2certifier/examples/nginx/nginx_acme_srv.conf /etc/nginx/sites-available/acme_srv.conf && \
    rm -f /var/www/acme2certifier/acme_srv/acme_srv.cfg && \
    chown -R www-data /var/www/acme2certifier && \
    ln -s /etc/nginx/sites-available/acme_srv.conf /etc/nginx/sites-enabled/acme_srv.conf && \
    sed -i "s/nginx/www-data/g" /var/www/acme2certifier/acme2certifier.ini && \
    ln -sf /dev/stdout /var/log/nginx/access.log && ln -sf /dev/stderr /var/log/nginx/error.log && \
    sed -i "s/default = default_sect/\default = default_sect\nlegacy = legacy_sect/g" /etc/ssl/openssl.cnf && \
    sed -i "s/\[default_sect\]/\[default_sect\]\nactivate = 1\n\[legacy_sect\]\nactivate = 1/g" /etc/ssl/openssl.cnf && \
    rm /etc/nginx/sites-enabled/default && \
    rm -rf /var/www/acme2certifier/examples/Docker && \
    rm -rf /var/www/acme2certifier/examples/django && \
    rm -rf /var/www/acme2certifier/examples/db_handler && \
    rm -rf /var/www/acme2certifier/examples/apache2 && \
    rm -rf /var/www/acme2certifier/examples/acme_srv.db.example && \
    rm -rf /var/www/acme2certifier/examples/acme2certifier_wsgi.py  && \
    chmod a+rx /docker-entrypoint.sh  # NOSONAR

COPY ./examples/nginx/supervisord.conf /etc

WORKDIR /var/www/acme2certifier

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/usr/bin/supervisord"]
# CMD ["/bin/bash"]

EXPOSE 80 443
