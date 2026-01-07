FROM ubuntu:24.04
LABEL maintainer="grindelsack@gmail.com"

RUN apt-get update  && \
    DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends tzdata && \
    DEBIAN_FRONTEND="noninteractive" apt-get install --no-install-recommends -y \
    curl \
    krb5-user \
    libgssapi-krb5-2 \
    libkrb5-3 \
    nginx \
    python3-django \
    python3-gssapi \
    python3-mysqldb \
    python3-pip \
    python3-psycopg2 \
    python3-pymysql \
    python3-yaml \
    uwsgi \
    uwsgi-plugin-python3 \
    && rm -rf /var/lib/apt/lists/* &&\
    mkdir -p /var/www/acme2certifier/volume && \
    mkdir -p /var/www/acme2certifier/examples /var/www/acme2certifier/examples/ && \
    mkdir -p /run/uwsgi

COPY ./ /var/www/acme2certifier/

RUN pip3 install impacket --break-system-packages && \
    rm /usr/local/bin/*.py && \
    rm -rf /usr/local/lib/python3.12/dist-packages/impacket/examples/* && \
    pip3 install -r /var/www/acme2certifier/requirements.txt --break-system-packages && \
    pip3 install supervisor --break-system-packages && \
    cp -R /var/www/acme2certifier/examples/django/* /var/www/acme2certifier/  && \
    cp /var/www/acme2certifier/examples/db_handler/django_handler.py /var/www/acme2certifier/acme_srv/db_handler.py  && \
	cp /var/www/acme2certifier/examples/nginx/acme2certifier.ini /var/www/acme2certifier && \
	cp /var/www/acme2certifier/examples/nginx/nginx_acme_srv.conf /etc/nginx/sites-available/acme_srv.conf && \
	cp /var/www/acme2certifier/examples/nginx/supervisord.conf /etc && \
	ln -s /etc/nginx/sites-available/acme_srv.conf /etc/nginx/sites-enabled/acme_srv.conf && \
	chown -R www-data:www-data /var/www/acme2certifier && \
    cp /var/www/acme2certifier/examples/Docker/nginx/django/docker-entrypoint.sh /docker-entrypoint.sh && \
    sed -i "s/acme2certifier_wsgi/acme2certifier.wsgi/g" /var/www/acme2certifier/acme2certifier.ini && \
    sed -i "s/nginx/www-data/g" /var/www/acme2certifier/acme2certifier.ini && \
    ln -sf /dev/stdout /var/log/nginx/access.log && ln -sf /dev/stderr /var/log/nginx/error.log && \
    sed -i "s/default = default_sect/\default = default_sect\nlegacy = legacy_sect/g" /etc/ssl/openssl.cnf && \
    sed -i "s/\[default_sect\]/\[default_sect\]\nactivate = 1\n\[legacy_sect\]\nactivate = 1/g" /etc/ssl/openssl.cnf && \
    rm /etc/nginx/sites-enabled/default && \
    rm /var/www/acme2certifier/CHANGES.md && \
    rm /var/www/acme2certifier/README.md && \
    rm /var/www/acme2certifier/SECURITY.md && \
    rm /var/www/acme2certifier/setup.py && \
    rm /var/www/acme2certifier/requirements.txt && \
	rm -rf /var/www/acme2certifier/examples/Docker && \
    rm -rf /var/www/acme2certifier/examples/db_handler && \
    rm -rf /var/www/acme2certifier/examples/apache2 && \
    rm -rf /var/www/acme2certifier/examples/acme_srv.db.example && \
    rm -rf /var/www/acme2certifier/examples/acme2certifier_wsgi.py  && \
	rm /var/www/acme2certifier/acme2certifier/settings.py && \
	chmod a+rx /docker-entrypoint.sh  # NOSONAR

WORKDIR /var/www/acme2certifier/

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["/usr/local/bin/supervisord"]

EXPOSE 80 443
