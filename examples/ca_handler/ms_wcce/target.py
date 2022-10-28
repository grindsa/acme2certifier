""" target class """
# pylint: disable=C0209, C0415, R0913, W1201
import logging
import socket
from dns.resolver import Resolver


def is_ip(hostname: str) -> bool:
    """ check if sring is an ip """
    try:
        # Check if hostname is an IP
        socket.inet_aton(hostname)
        result = True
    except Exception:
        result = False
    return result


class DnsResolver:
    """ DNS resolver class """
    def __init__(self):
        self.resolver = Resolver()

        self.mappings = {}

    @staticmethod
    def from_options(options, target) -> "DnsResolver":
        """ setup resolver object from given options """
        self = DnsResolver()

        # We can't put all possible nameservers in the list of nameservers, since
        # the resolver will fail if one of them fails
        nameserver = options.ns
        if nameserver is None:
            nameserver = target.dc_ip

        if nameserver is not None:
            self.resolver.nameservers = [nameserver]
        # pylint: disable=W0201
        self.use_tcp = options.dns_tcp

        return self

    @staticmethod
    def create(
        target: "Target" = None, ns_: str = None, dns_tcp: bool = False
    ) -> "DnsResolver":
        """ setup resolver object without options """
        self = DnsResolver()

        # We can't put all possible nameservers in the list of nameservers, since
        # the resolver will fail if one of them fails
        nameserver = ns_
        if nameserver is None:
            nameserver = target.dc_ip

        if nameserver is not None:
            self.resolver.nameservers = [nameserver]

        # pylint: disable=W0201
        self.use_tcp = dns_tcp

        return self

    def resolve(self, hostname: str) -> str:
        """ Try to resolve the hostname with DNS first, then try a local resolve """
        if hostname in self.mappings:
            logging.debug(
                "Resolved %s from cache: %s" % (repr(hostname), self.mappings[hostname])
            )
            return self.mappings[hostname]

        if is_ip(hostname):
            return hostname

        ip_addr = None
        if self.resolver.nameservers[0] is None:
            logging.debug("Trying to resolve %s locally" % repr(hostname))
        else:
            logging.debug(
                "Trying to resolve %s at %s"
                % (repr(hostname), repr(self.resolver.nameservers[0]))
            )
        try:
            answers = self.resolver.resolve(hostname, tcp=self.use_tcp)
            if len(answers) == 0:
                raise SystemError()

            ip_addr = answers[0].to_text()
        except Exception as err_:
            logging.debug('Error resolving %s : %s' % (repr(hostname), err_))

        if ip_addr is None:
            try:
                ip_addr = socket.gethostbyname(hostname)
            except Exception:
                ip_addr = None

        if ip_addr is None:
            logging.warning("Failed to resolve: %s" % hostname)
            return hostname

        self.mappings[hostname] = ip_addr
        return ip_addr


class Target:
    """ target class """
    def __init__(
        self,
        domain: str = None,
        username: str = None,
        password: str = None,
        target_ip: str = None,
        remote_name: str = None,
        no_pass: bool = False,
        dc_ip: str = None,
        ns_: str = None,
        dns_tcp: bool = False,
        timeout: int = 5,
    ):
        if domain is None:
            domain = ""

        if password == "" and username != "" and no_pass is not True:
            from getpass import getpass

            password = getpass("Password:")

        lmhash = nthash = ""

        self.domain = domain
        self.username = username
        self.password = password
        self.remote_name = remote_name
        self.lmhash = lmhash
        self.nthash = nthash
        self.dc_ip = dc_ip
        self.timeout = timeout

        if ns_ is None:
            ns_ = dc_ip

        if is_ip(remote_name):
            target_ip = remote_name

        self.resolver = DnsResolver.create(self, ns_=ns_, dns_tcp=dns_tcp)

        self.target_ip = target_ip
        if self.target_ip is None and remote_name is not None:
            self.target_ip = self.resolver.resolve(remote_name)

    def __repr__(self) -> str:
        return "<Target (%s)>" % repr(self.__dict__)
