FROM ubuntu:22.04
LABEL maintainer="grindelsack@gmail.com"

ARG BRANCH
RUN apt-get update
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata
RUN apt-get install --no-install-recommends -y \
    python3-pip \
    nginx \
    uwsgi \
    uwsgi-plugin-python3 \
    curl \
    python3-django \
    python3-mysqldb \
    python3-pymysql \
    python3-psycopg2 \
    python3-yaml \
 && rm -rf /var/lib/apt/lists/*

# install python requirements
COPY requirements.txt /tmp/requirements.txt
# RUN pip3 install -r /tmp/requirements.txt

RUN pip3 install -r /tmp/requirements.txt && \
    pip3 install supervisor django_rename_app==0.1.3

# create folders for acme2certifier
RUN mkdir -p /var/www/acme2certifier/volume && \
    mkdir -p /var/www/acme2certifier/examples && \
    mkdir -p /run/uwsgi

COPY examples/django/ /var/www/acme2certifier/
COPY examples/django/ /var/www/acme2certifier/examples/django
COPY examples/ca_handler/ /var/www/acme2certifier/examples/ca_handler
COPY examples/eab_handler/ /var/www/acme2certifier/examples/eab_handler
COPY examples/hooks/ /var/www/acme2certifier/examples/hooks
COPY examples/acme_srv.cfg /var/www/acme2certifier/examples/
COPY examples/nginx/ /var/www/acme2certifier/examples/nginx
COPY acme_srv/ /var/www/acme2certifier/acme_srv
COPY tools/ /var/www/acme2certifier/tools
COPY examples/db_handler/django_handler.py /var/www/acme2certifier/acme_srv/db_handler.py
COPY examples/nginx/acme2certifier.ini /var/www/acme2certifier
COPY examples/nginx/nginx_acme_srv.conf /etc/nginx/sites-available/acme_srv.conf
COPY examples/nginx/supervisord.conf /etc
RUN  chown -R www-data /var/www/acme2certifier/acme_srv && \
     rm /etc/nginx/sites-enabled/default && \
     ln -s /etc/nginx/sites-available/acme_srv.conf /etc/nginx/sites-enabled/acme_srv.conf

RUN chown -R www-data:www-data /var/www/acme2certifier/
RUN rm /var/www/acme2certifier/acme2certifier/settings.py && \
    sed -i "s/acme2certifier_wsgi/acme2certifier.wsgi/g" /var/www/acme2certifier/acme2certifier.ini && \
    sed -i "s/nginx/www-data/g" /var/www/acme2certifier/acme2certifier.ini

# allow  md4 algorithm in openssl for msca handler
RUN sed -i "s/default = default_sect/\default = default_sect\nlegacy = legacy_sect/g" /etc/ssl/openssl.cnf && \
    sed -i "s/\[default_sect\]/\[default_sect\]\nactivate = 1\n\[legacy_sect\]\nactivate = 1/g" /etc/ssl/openssl.cnf

COPY examples/Docker/nginx/django/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod a+rx /docker-entrypoint.sh

WORKDIR /var/www/acme2certifier/

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["/usr/local/bin/supervisord"]

EXPOSE 80 443
