"""Network allowlist for the headless client -- let it reach ONLY Growtopia (+ localhost).

Everything the bot legitimately touches is Growtopia: HTTPS to login.growtopiagame.com and
www.growtopia1/2.com (auth + server_data), and UDP to the ENet game servers (213.179.x). This installs
application socket guards for destination restrictions. This is not an OS firewall
or a security boundary against arbitrary code. In proxy mode, physical destinations
are limited to the proxy and negotiated UDP relays; proxy_transport checks the
logical Growtopia destinations. Call install() before network use. Blocks raise
NetBlocked (an OSError), which the auth/reconnect paths already handle.
"""
import socket
import ipaddress

# Growtopia HTTPS hosts (exact), and the game-server IP range server_data/redirects hand us.
DEFAULT_HOSTS = ("login.growtopiagame.com", "www.growtopiagame.com", "growtopiagame.com",
                 "www.growtopia1.com", "www.growtopia2.com")
DEFAULT_CIDRS = ("213.179.192.0/18",)          # GT/Ubisoft ENet game-server subnet (covers 213.179.209.x)

_HOSTS = set()
_NETS = []
_IPS = set()                                   # resolved IPs of allowed hosts + any explicitly added
_installed = False
_PROXY_ENDPOINT = None
_PROXY_RELAYS = {}


def lock_to_proxy(address):
    """Restrict socket destinations to the proxy; logical GT checks remain separate."""
    global _PROXY_ENDPOINT
    _PROXY_ENDPOINT = tuple(address[:2])


def allow_proxy_relay(address):
    key = tuple(address[:2])
    _PROXY_RELAYS[key] = _PROXY_RELAYS.get(key, 0) + 1


def remove_proxy_relay(address):
    key = tuple(address[:2])
    count = _PROXY_RELAYS.get(key, 0) - 1
    if count > 0:
        _PROXY_RELAYS[key] = count
    else:
        _PROXY_RELAYS.pop(key, None)


def _transport_allowed(sock, address):
    key = tuple(address[:2])
    return (sock.type == socket.SOCK_STREAM and key == _PROXY_ENDPOINT or
            sock.type == socket.SOCK_DGRAM and key in _PROXY_RELAYS)


class NetBlocked(OSError):
    pass


def allow_host(h):
    _HOSTS.add(str(h).lower().strip("."))


def allow_cidr(c):
    _NETS.append(ipaddress.ip_network(c, strict=False))


def allow_ip(ip):
    try:
        _IPS.add(str(ipaddress.ip_address(ip)))
    except ValueError:
        pass


def _ip_allowed(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.is_loopback:                          # localhost is always fine (no external exposure)
        return True
    if str(a) in _IPS:
        return True
    return any(a in n for n in _NETS)


def _host_allowed(h):
    h = str(h).lower().strip(".")
    if h in _HOSTS:
        return True
    try:                                       # IP-literal host (e.g. the ENet server): check the IP
        ipaddress.ip_address(h)
        return _ip_allowed(h)
    except ValueError:
        return False


_orig_gai = socket.getaddrinfo
_orig_connect = socket.socket.connect
_orig_connect_ex = socket.socket.connect_ex
_orig_sendto = socket.socket.sendto


def _gai(host, *a, **k):
    h = host.decode() if isinstance(host, (bytes, bytearray)) else host
    if h is not None and not _host_allowed(h):
        raise NetBlocked("netguard: DNS/connect to %r blocked (not a Growtopia host)" % h)
    res = _orig_gai(host, *a, **k)
    for item in res:                           # a resolved IP of an allowed host becomes connect-allowed
        try:
            allow_ip(item[4][0])
        except Exception:
            pass
    return res


def _connect(self, address):
    if _PROXY_ENDPOINT is not None:
        if not _transport_allowed(self, address):
            raise NetBlocked("netguard: direct connection forbidden in proxy mode")
        return _orig_connect(self, address)
    ip = address[0] if isinstance(address, (tuple, list)) else None
    if ip is not None and not _ip_allowed(ip):
        raise NetBlocked("netguard: connect to %s blocked (not a Growtopia address)" % (address,))
    return _orig_connect(self, address)


def _sendto(self, data, *args):
    address = args[-1] if args else None
    if _PROXY_ENDPOINT is not None:
        if not _transport_allowed(self, address):
            raise NetBlocked("netguard: direct datagram forbidden in proxy mode")
        return _orig_sendto(self, data, *args)
    ip = address[0] if isinstance(address, (tuple, list)) else None
    if ip is not None and not _ip_allowed(ip):
        raise NetBlocked("netguard: sendto %s blocked (not a Growtopia address)" % (address,))
    return _orig_sendto(self, data, *args)


def _connect_ex(self, address):
    if _PROXY_ENDPOINT is not None:
        if not _transport_allowed(self, address):
            raise NetBlocked("netguard: direct connection forbidden in proxy mode")
    elif not _ip_allowed(address[0]):
        raise NetBlocked("netguard: connection destination blocked")
    return _orig_connect_ex(self, address)


def install(hosts=DEFAULT_HOSTS, cidrs=DEFAULT_CIDRS):
    """Install the guards (idempotent). After this, outbound to anything but Growtopia/localhost is refused."""
    global _installed
    for h in hosts:
        allow_host(h)
    for c in cidrs:
        allow_cidr(c)
    if not _installed:
        socket.getaddrinfo = _gai
        socket.socket.connect = _connect
        socket.socket.connect_ex = _connect_ex
        socket.socket.sendto = _sendto
        _installed = True
    return sorted(_HOSTS), [str(n) for n in _NETS]
