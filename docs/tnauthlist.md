<!-- markdownlint-disable  MD013 -->
<!-- wiki-title Support for TNAuthList identifier and tkauth 01 challenges -->
# TNAuthList support

The support of TNAuthList identifier and tkauth-01 challenges is rather experimental. Main reason is that neither identifier nor challenge type are fully standardized.

The current implementation follows:

- [draft-ietf-acme-authority-token-tnauthlist-08](https://datatracker.ietf.org/doc/html/draft-ietf-acme-authority-token-tnauthlist-08)
- [draft-ietf-acme-authority-token-07](https://tools.ietf.org/html/draft-ietf-acme-authority-token-tnauthlist-07)
- [ATIS-1000080](https://access.atis.org/apps/group_public/document.php?document_id=55537)

TNAuthList support is disabled by default and needs to be enabled in [acme_srv.cfg](acme_srv.md) by adding the parameter `tnauthlist_support: True` into the `Order` section of the configuration file.

There is currently no acme-client available supporting the TNAuthList extension. For testing purposes, I added the needed support to [acme.sh](https://github.com/grindsa/acme.sh)
but the changes are not yet incorporated into the main code. So, feel free to use it at your own risk and don't forget to provide feedback.

Below the command to be used enroll the certificate having a TNAuthList certificate extension

`root@rlh:~# acme.sh --server http://<server-name> --issue -d <fqdn> --tnauth <TN Authorization List> --spctoken <service provider code token> --standalone -w /tmp --debug 2 --output-insecure --force --log acme.log'`
