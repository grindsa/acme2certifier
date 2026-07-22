<!-- markdownlint-disable  MD013 -->

<!-- wiki-title Containerized installation -->

# Containerized installation using apache2/nginx as webserver and wsgi or django

See [acme2certifier in Docker](../examples/Docker/README.md).

Images are Ubuntu **26.04**-based and install from a prebuilt `.deb`. Each variant bakes `ACME_SRV_DB_HANDLER` (`wsgi` or `django`); `[DBhandler]` in `acme_srv.cfg` still wins if set. Changing the handler in cfg does not switch the Apache/nginx app entry — pick the matching image tag for the web stack.
