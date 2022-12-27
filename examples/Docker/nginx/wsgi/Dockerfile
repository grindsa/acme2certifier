FROM ubuntu:22.04
LABEL maintainer="grindelsack@gmail.com"
RUN apt-get update  && \
    DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata && \
    apt-get install --no-install-recommends -y \
    python3-pip \
    nginx \
    uwsgi \
    uwsgi-plugin-python3 \
    curl \
    && rm -rf /var/lib/apt/lists/* &&\
    mkdir -p /var/www/acme2certifier/volume && \
    mkdir -p /var/www/acme2certifier/examples /var/www/acme2certifier/examples/ && \
    mkdir -p /run/uwsgi

COPY ./ /var/www/acme2certifier/

# configure acme2certifier
RUN pip3 install -r /var/www/acme2certifier/requirements.txt && pip3 install supervisor && \
    cp /var/www/acme2certifier/examples/acme2certifier_wsgi.py /var/www/acme2certifier/acme2certifier_wsgi.py && \
    cp /var/www/acme2certifier/examples/db_handler/wsgi_handler.py /var/www/acme2certifier/acme_srv/db_handler.py && \
	cp /var/www/acme2certifier/examples/nginx/acme2certifier.ini /var/www/acme2certifier && \
	cp /var/www/acme2certifier/examples/nginx/nginx_acme_srv.conf /etc/nginx/sites-available/acme_srv.conf && \
	cp /var/www/acme2certifier/examples/nginx/supervisord.conf /etc && \
	chown -R www-data /var/www/acme2certifier && \
	ln -s /etc/nginx/sites-available/acme_srv.conf /etc/nginx/sites-enabled/acme_srv.conf && \
    cp /var/www/acme2certifier/examples/Docker/nginx/wsgi/docker-entrypoint.sh /docker-entrypoint.sh && \
    # echo "plugins=python3" >> /var/www/acme2certifier/acme2certifier.ini && \
    sed -i "s/nginx/www-data/g" /var/www/acme2certifier/acme2certifier.ini && \
	sed -i "s/default = default_sect/\default = default_sect\nlegacy = legacy_sect/g" /etc/ssl/openssl.cnf && \
    sed -i "s/\[default_sect\]/\[default_sect\]\nactivate = 1\n\[legacy_sect\]\nactivate = 1/g" /etc/ssl/openssl.cnf && \
	rm /etc/nginx/sites-enabled/default && \
    rm /var/www/acme2certifier/CHANGES.md /var/www/acme2certifier/README.md /var/www/acme2certifier/SECURITY.md /var/www/acme2certifier/setup.py /var/www/acme2certifier/requirements.txt && \
	rm -rf /var/www/acme2certifier/examples/Docker /var/www/acme2certifier/examples/django /var/www/acme2certifier/examples/db_handler /var/www/acme2certifier/examples/apache2 /var/www/acme2certifier/examples/acme_srv.db.example /var/www/acme2certifier/examples/acme2certifier_wsgi.py  && \
	chmod a+rx /docker-entrypoint.sh

WORKDIR /var/www/acme2certifier

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["/usr/local/bin/supervisord"]

# CMD ["/bin/bash"]

EXPOSE 80 443
