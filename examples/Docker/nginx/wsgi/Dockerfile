FROM ubuntu:20.04
LABEL maintainer="grindelsack@gmail.com"

RUN apt-get update
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata
RUN apt-get install --no-install-recommends -y \
    python3-pip \
    nginx \
    uwsgi \
    uwsgi-plugin-python3 \
    curl \
    python3-cryptography \
&& rm -rf /var/lib/apt/lists/*

# install python requirements
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt && \
    pip3 install supervisor


RUN mkdir -p /var/www/acme2certifier/volume && \
    mkdir -p /var/www/acme2certifier/examples && \
    mkdir -p /run/uwsgi

COPY examples/acme2certifier_wsgi.py /var/www/acme2certifier/acme2certifier_wsgi.py
COPY examples/ca_handler/ /var/www/acme2certifier/examples/ca_handler
COPY examples/eab_handler/ /var/www/acme2certifier/examples/eab_handler
COPY examples/nginx/ /var/www/acme2certifier/examples/nginx
COPY examples/acme_srv.cfg /var/www/acme2certifier/examples/
COPY acme/ /var/www/acme2certifier/acme
COPY tools/ /var/www/acme2certifier/tools
COPY examples/db_handler/wsgi_handler.py /var/www/acme2certifier/acme/db_handler.py
COPY examples/nginx/acme2certifier.ini /var/www/acme2certifier
COPY examples/nginx/nginx_acme.conf /etc/nginx/sites-available/acme.conf
COPY examples/nginx/supervisord.conf /etc
RUN  chown -R www-data /var/www/acme2certifier/acme && \
     rm /etc/nginx/sites-enabled/default && \
     ln -s /etc/nginx/sites-available/acme.conf /etc/nginx/sites-enabled/acme.conf


COPY examples/Docker/nginx/wsgi/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod a+rx /docker-entrypoint.sh && \
    # echo "plugins=python3" >> /var/www/acme2certifier/acme2certifier.ini
    sed -i "s/nginx/www-data/g" /var/www/acme2certifier/acme2certifier.ini


# final nginx changes
#RUN sed -i "s/ default_server\;/\;/g" /etc/nginx/nginx.conf

WORKDIR /var/www/acme2certifier

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["/usr/local/bin/supervisord"]

# CMD ["/bin/bash"]

EXPOSE 80 443
