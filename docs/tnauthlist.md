<!-- markdownlint-disable  MD013 -->
# TNAuthList support

The support of TNAuthList identifier and tkauth-01 challenges is rather experimental. Main reason is that neither identifier nor challenge type are fully standardized.

The current implementation follows:

- [draft-ietf-acme-authority-token-tnauthlist-03](https://tools.ietf.org/html/draft-ietf-acme-authority-token-tnauthlist-03)
- [draft-ietf-acme-authority-token-03](https://tools.ietf.org/html/draft-ietf-acme-authority-token-03)
- [ATIS-1000080e](https://access.atis.org/apps/group_public/document.php?document_id=50027) (link points to an older document as ATIS-1000080e is not publicly avaialbe)

TNAuthList support is disabled by default and needs to be enabled in [acme_srv.cfg](acme_srv.md) by adding the parameter `tnauthlist_support: True` into the `Order` section of the configuration file.

There is currently no acme-client available supporting the TNAuthList extension. For testing purposes, I added the needed support to [acme.sh](https://github.com/grindsa/acme.sh)
but the changes are not yet incorporated into the main code. So, feel free to use it at your own risk and don't forget to provide feedback.

Below the command to be used enroll the certificate having a TNAuthList certificate extension

`root@rlh:~# acme.sh --server http://<server-name> --issue -d <fqdn> --tnauth <TN Authorization List> --spctoken <service provider code token> --standalone -w /tmp --debug 2 --output-insecure --force --log acme.log'`
