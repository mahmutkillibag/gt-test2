"""Small SOCKS5 transport for HTTPS and ENet. No direct fallback; stdlib only.

Protocol reference: RFC 1928/1929. Mori's UDP socket/test design informed the
integration; this implementation keeps TLS verification and validates replies.
"""
import http.client
import ipaddress
import select
import socket
import struct
import urllib.request
import urllib.parse

_proxy = None


class ProxyError(OSError):
    pass


def parse_endpoint(value):
    parsed = urllib.parse.urlsplit(value if "://" in value else "socks5://" + value)
    if parsed.scheme not in ("socks5", "socks5h") or not parsed.hostname or not parsed.port:
        raise ValueError("expected SOCKS5 host:port or user:password@host:port")
    if parsed.path or parsed.query or parsed.fragment:
        raise ValueError("proxy endpoint must not contain a path, query, or fragment")
    result = {"host": parsed.hostname, "port": parsed.port}
    if parsed.username is not None:
        result.update(username=urllib.parse.unquote(parsed.username),
                      password=urllib.parse.unquote(parsed.password or ""))
    return result


def _exact(sock, count):
    result = bytearray()
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise ProxyError("SOCKS5 control connection closed")
        result.extend(part)
    return bytes(result)


def _address(host, port):
    try:
        ip = ipaddress.ip_address(host)
        data = bytes([1 if ip.version == 4 else 4]) + ip.packed
    except ValueError:
        name = host.encode("idna")
        if not 0 < len(name) <= 255:
            raise ProxyError("invalid SOCKS5 hostname length")
        data = b"\x03" + bytes([len(name)]) + name
    return data + struct.pack("!H", int(port))


def _read_address(read, kind):
    if kind == 1:
        host = str(ipaddress.ip_address(read(4)))
    elif kind == 4:
        host = str(ipaddress.ip_address(read(16)))
    elif kind == 3:
        host = read(read(1)[0]).decode("ascii")
    else:
        raise ProxyError("unsupported SOCKS5 address type")
    return host, struct.unpack("!H", read(2))[0]


def configure(value):
    """Configure once before networking. Null retains the original direct mode."""
    global _proxy
    if value is None:
        _proxy = None
        return
    if not isinstance(value, dict) or not value.get("host") or not value.get("port"):
        raise ValueError("proxy must contain host and port (or be null for direct mode)")
    port = int(value["port"])
    if not 1 <= port <= 65535:
        raise ValueError("invalid proxy port")
    if bool(value.get("username")) != bool(value.get("password")):
        raise ValueError("proxy username and password must be supplied together")
    info = socket.getaddrinfo(value["host"], port, type=socket.SOCK_STREAM)[0]
    _proxy = dict(value, family=info[0], endpoint=info[4], port=port)


def enabled():
    return _proxy is not None


def endpoint():
    return _proxy["endpoint"][:2]


def _open(command, target, timeout):
    if _proxy is None:
        raise ProxyError("proxy transport is not configured")
    sock = socket.socket(_proxy["family"], socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect(_proxy["endpoint"])
        user = _proxy.get("username", "").encode()
        password = _proxy.get("password", "").encode()
        if len(user) > 255 or len(password) > 255:
            raise ProxyError("SOCKS5 credentials exceed 255 bytes")
        methods = b"\x00\x02" if user else b"\x00"
        sock.sendall(b"\x05" + bytes([len(methods)]) + methods)
        version, method = _exact(sock, 2)
        if version != 5 or method not in methods:
            raise ProxyError("SOCKS5 authentication method rejected")
        if method == 2:
            sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
            if _exact(sock, 2) != b"\x01\x00":
                raise ProxyError("SOCKS5 authentication failed")
        sock.sendall(b"\x05" + bytes([command, 0]) + _address(*target))
        version, reply, reserved, kind = _exact(sock, 4)
        if version != 5 or reserved != 0:
            raise ProxyError("invalid SOCKS5 reply")
        if reply:
            raise ProxyError("SOCKS5 command %d refused (reply %d)" % (command, reply))
        bound = _read_address(lambda n: _exact(sock, n), kind)
        return sock, bound
    except BaseException:
        sock.close()
        raise


def _check_target(host):
    import netguard
    if not netguard._host_allowed(host):
        raise ProxyError("destination is outside the Growtopia allowlist")


class _HTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        _check_target(self.host)
        if self.port != 443 or self._tunnel_host:
            raise ProxyError("only Growtopia HTTPS port 443 is allowed")
        self.sock, _ = _open(1, (self.host, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)
        except BaseException:
            self.sock.close()
            raise


class HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_HTTPSConnection, req, context=self._context)


class NoHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        raise ProxyError("unencrypted HTTP is disabled in proxy mode")


class SocksUDP:
    def __init__(self, timeout=10):
        self.control = self.sock = None
        self.relay = None
        self._relay_registered = False
        try:
            if _proxy is None:
                raise ProxyError("proxy transport is not configured")
            # Bind first: some relays accept port zero but silently discard the
            # datagrams. Advertise the real local port, with an unspecified IP
            # so a private LAN address is not mistaken for our public NAT IP.
            family = _proxy["family"]
            self.sock = socket.socket(family, socket.SOCK_DGRAM)
            local_host = "::" if family == socket.AF_INET6 else "0.0.0.0"
            self.sock.bind((local_host, 0))
            local_port = self.sock.getsockname()[1]
            self.control, (host, port) = _open(3, (local_host, local_port), timeout)
            if not port:
                raise ProxyError("SOCKS5 returned a zero relay port")
            try:
                unspecified = ipaddress.ip_address(host).is_unspecified
            except ValueError:
                unspecified = False
            if unspecified:
                host = endpoint()[0]
            import netguard
            info = netguard._orig_gai(host, port, type=socket.SOCK_DGRAM)[0]
            self.relay = info[4]
            # A public proxy must not redirect us into the local network.
            if ipaddress.ip_address(endpoint()[0]).is_global and not ipaddress.ip_address(self.relay[0]).is_global:
                # Some NATed proxies advertise their private bind address. Try
                # the same port on the public proxy, never that private address.
                info = netguard._orig_gai(endpoint()[0], port, type=socket.SOCK_DGRAM)[0]
                self.relay = info[4]
            netguard.allow_proxy_relay(self.relay)
            self._relay_registered = True
            if info[0] != family:
                self.sock.close()
                self.sock = socket.socket(info[0], socket.SOCK_DGRAM)
                self.sock.bind(("::" if info[0] == socket.AF_INET6 else "0.0.0.0", local_port))
            self.sock.connect(self.relay)  # kernel filters packets from other sources
            self.sock.setblocking(False)
        except BaseException:
            self.close()
            raise

    def _alive(self):
        if self.control is None:
            raise ProxyError("SOCKS5 UDP transport is closed")
        ready, _, _ = select.select([self.control], [], [], 0)
        if ready:
            raise ProxyError("SOCKS5 UDP control connection ended or sent unexpected data")

    def setblocking(self, value):
        self.sock.setblocking(value)

    def sendto(self, data, target):
        self._alive()
        _check_target(target[0])
        header = b"\x00\x00\x00" + _address(*target)
        count = self.sock.send(header + data)
        return max(0, count - len(header))

    def recvfrom(self, size):
        self._alive()
        data = self.sock.recv(size + 262)
        if len(data) < 4 or data[:3] != b"\x00\x00\x00":
            raise BlockingIOError("discarded malformed or fragmented SOCKS5 datagram")
        pos = 4

        def read(n):
            nonlocal pos
            if pos + n > len(data):
                raise ProxyError("truncated SOCKS5 datagram")
            result = data[pos:pos+n]
            pos += n
            return result
        try:
            target = _read_address(read, data[3])
            _check_target(target[0])
        except (OSError, ValueError, UnicodeError):
            raise BlockingIOError("discarded invalid SOCKS5 datagram")
        return data[pos:pos+size], target

    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None
        if self.control is not None:
            self.control.close()
            self.control = None
        if self._relay_registered:
            import netguard
            netguard.remove_proxy_relay(self.relay)
            self._relay_registered = False
        self.relay = None
