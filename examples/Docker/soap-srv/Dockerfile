FROM ubuntu:22.04
LABEL maintainer="grindelsack@gmail.com"

RUN apt-get update
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata
RUN apt-get install --no-install-recommends -y \
    python3-pip \
    curl \
 && rm -rf /var/lib/apt/lists/*

# install python requirements
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt


# create folders for acme2certifier
RUN mkdir -p /usr/local/soap-srv/acme_srv && \
	mkdir -p /usr/local/soap-srv/examples/ca_handler

COPY examples/soap/mock_soap_srv.py /usr/local/soap-srv/
COPY acme_srv/helper.py acme_srv/version.py /usr/local/soap-srv/acme_srv/
COPY examples/ca_handler/xca_ca_handler.py /usr/local/soap-srv/examples/ca_handler/xca_ca_handler.py
COPY examples/Docker/soap-srv/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod a+rx /docker-entrypoint.sh

WORKDIR /tmp

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["python3", "/usr/local/soap-srv/mock_soap_srv.py", "-d", "-c", "/etc/soap-srv/soap_srv.cfg"]
# CMD ["/bin/bash"]

EXPOSE 80
