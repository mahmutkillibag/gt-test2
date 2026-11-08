"""Minimal ENet client for Growtopia (send side), with GT's real custom framing.

GT runs Ubisoft's "new packet" ENet variant (server_data `type2|1`); the canonical open-source
implementation is the ZTzTopia/enet fork. The client->server datagram is (all big-endian):

  ENetNewProtocolHeader (10 bytes, packed):
    [0:2]   integrity[0] = randomAroundPort           (random value in [0, serverPort])
    [2:4]   integrity[1] = randomAroundPort ^ port     (XORs back to the server port -> self-validating)
    [4:6]   integrity[2] = (random & 0xf3df) | 0x920d  (random noise around a fixed 0x920d marker)
    [6:8]   peerID word  = outgoingPeerID | (session<<12) | flags
            (unconnected CONNECT: outgoingPeerID = 0x0FFF; flags = 0x8000 SENT_TIME [| 0x4000 COMPRESSED])
    [8:10]  sentTime     = serviceTime & 0xffff        (ms since client start; server echoes it)
  [10:14] checksum = crc32( header[0:10] + seedSlot(4) + DECOMPRESSED_commands ), big-endian.
          seedSlot = 0 before VERIFY_CONNECT (outgoingPeerID unassigned), = peer connectID after.
  [14:]   body = range-coder COMPRESS(commands) when it shrinks (COMPRESSED flag set), else raw commands.

Confirmed against the real login2.pcapng CONNECT (port 17047=0x4297): integrity[0]^integrity[1] =
0x0dca^0x4f5d = 0x4297 = the port; integrity[2]=0xd3cd has the 0x920d marker; peerID word 0xcfff =
0x0FFF | 0xC000. So the header is pure port-XOR + randomness (the compiler VM-virtualized a trivial
computation); no device fingerprint and no emulation are needed. Receive side reuses core/gt_decode.
Nothing here is crafted/exploit traffic; it is the standard ENet protocol a normal client speaks.
"""
import os, socket, struct, time, zlib, sys, random
import proxy_transport as proxy

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "core"))
from gt_decode import _decompress
from rangecoder import compress as rc_compress

ACKNOWLEDGE, CONNECT, VERIFY_CONNECT, DISCONNECT, PING = 1, 2, 3, 4, 5
SEND_RELIABLE, SEND_UNRELIABLE, SEND_FRAGMENT = 6, 7, 8
FLAG_ACK = 0x80
F_SENT_TIME, F_COMPRESSED = 0x8000, 0x4000
CMD_SIZES = {0: 0, 1: 8, 2: 48, 3: 44, 4: 8, 5: 6, 6: 8, 7: 8, 8: 24, 9: 8, 10: 12, 11: 16, 12: 24}

PEER_PING_INTERVAL = 0.5
RELIABLE_TIMEOUT = 0.4
RECV_TIMEOUT = 20.0        # if no datagram arrives for this long once connected, treat the link as dead
                          # (covers a silent drop -- cut internet/server timeout where no DISCONNECT reaches us)

INTEG_MASK = 0xf3df       # integrity[2] random mask (real-binary constant; capture 0xd3cd fits it, not 0x61d2)
INTEG_MARK = 0x920d       # integrity[2] fixed marker
MAX_PEER_ID = 0x0FFF      # ENET_PROTOCOL_MAXIMUM_PEER_ID; CONNECT sends this as outgoingPeerID
SESSION_SHIFT = 12

# Endianness of the 4-byte checksum "seed slot" that the server pre-fills with connectID before
# recomputing crc32. The BE result byte-order is proven byte-exact vs the capture; the seed slot
# itself could not be distinguished on CONNECT (seed was 0 there). If the post-verify login is
# rejected while VERIFY_CONNECT still succeeds, flip this to "<I" (native little-endian memcpy).
SEED_SLOT = ">I"


class ENetError(Exception):
    pass


def gt_checksum(header10, commands, seed=0):
    """crc32 over [10-byte header + seed slot(4) + DECOMPRESSED commands], big-endian result.
    seed = 0 before VERIFY_CONNECT (outgoingPeerID unassigned), = peer connectID after."""
    inp = header10 + struct.pack(SEED_SLOT, seed & 0xFFFFFFFF) + commands
    return struct.pack(">I", zlib.crc32(inp) & 0xFFFFFFFF)


class ENetClient:
    def __init__(self, host, port, channel_count=2, transport=None):
        self.addr = (host, int(port))
        self.sock = transport if transport is not None else (
            proxy.SocksUDP() if proxy.enabled() else socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        self.sock.setblocking(False)
        self.channel_count = channel_count
        self.connect_id = random.getrandbits(32)
        self.outgoing_peer_id = MAX_PEER_ID       # unassigned until VERIFY_CONNECT (seed stays 0)
        self.connected = False
        self._t0 = time.time()                    # for serviceTime (ms since client start)
        self.sys_seq = 1
        self.out_seq = {ch: 1 for ch in range(channel_count + 2)}
        self.unacked = {}
        self.in_frag = {}
        self.last_recv = time.time()
        self.last_ping = 0.0
        self.on_message = None
        self.verbose = False
        self._rx = 0
        self.out_session = 0
        self._cur_sent_time = 0

    def _service_time(self):
        return int((time.time() - self._t0) * 1000) & 0xFFFF

    def _build_header(self, flags):
        """Build the 10-byte ENetNewProtocolHeader for this packet.

        The integrity array is self-validating (integrity[0] ^ integrity[1] == server port) and the
        marker word is random noise around 0x920d, so no PRNG seed or device value is needed -- any
        values satisfying the constraints are accepted. peerID word carries outgoingPeerID + session
        (post-verify) or 0x0FFF (pre-verify CONNECT), OR'd with the header flags."""
        port = self.addr[1] & 0xFFFF
        r0 = random.randint(0, port)                      # randomAroundPort in [0, port]
        integ0 = r0
        integ1 = r0 ^ port                                # server recovers port via integ0 ^ integ1
        integ2 = (random.getrandbits(16) & INTEG_MASK) | INTEG_MARK
        if self.connected:
            peer_word = (self.outgoing_peer_id & MAX_PEER_ID) | (self.out_session << SESSION_SHIFT) | flags
        else:
            peer_word = MAX_PEER_ID | flags               # unconnected CONNECT: session omitted
        sent = self._service_time()
        return struct.pack(">HHHHH", integ0, integ1, integ2, peer_word & 0xFFFF, sent)

    def _send_commands(self, commands):
        """Frame + send one datagram carrying `commands` (raw ENet command bytes)."""
        body_c = rc_compress(commands)
        if 0 < len(body_c) < len(commands):               # only flag COMPRESSED when it actually shrinks
            flags, body = F_SENT_TIME | F_COMPRESSED, body_c
        else:
            flags, body = F_SENT_TIME, commands
        header = self._build_header(flags)
        seed = self.connect_id if self.connected else 0   # 0 pre-verify, connectID post-verify
        csum = gt_checksum(header, commands, seed)         # checksum is over the *uncompressed* commands
        dgram = header + csum + body
        try:
            self.sock.sendto(dgram, self.addr)
        except proxy.ProxyError as exc:
            raise ENetError(str(exc)) from exc
        except OSError:
            pass                                          # network down; recv-timeout drives the reconnect
        return dgram

    def connect(self):
        seq = self.sys_seq; self.sys_seq += 1
        b = struct.pack(">BBH", CONNECT | FLAG_ACK, 0xFF, seq)
        b += struct.pack(">H", 0)                 # outgoingPeerID (our incomingPeerID)
        b += struct.pack(">BB", 0xFF, 0xFF)       # in/out sessionID
        b += struct.pack(">I", 1392)              # mtu (0x570, from capture)
        b += struct.pack(">I", 0x10000)           # windowSize
        b += struct.pack(">I", self.channel_count)
        b += struct.pack(">I", 0)                 # incomingBandwidth
        b += struct.pack(">I", 0)                 # outgoingBandwidth
        b += struct.pack(">I", 5000)              # packetThrottleInterval
        b += struct.pack(">I", 2)                 # accel
        b += struct.pack(">I", 2)                 # decel
        b += struct.pack(">I", self.connect_id)
        b += struct.pack(">I", 0)                 # data
        dg = self._send_commands(bytes(b))
        self.unacked[(0xFF, seq)] = [dg, time.time(), CONNECT, bytes(b)]

    def send_message(self, payload, channel=0):
        seq = self.out_seq[channel]; self.out_seq[channel] += 1
        hdr = struct.pack(">BBH", SEND_RELIABLE | FLAG_ACK, channel, seq)
        hdr += struct.pack(">H", len(payload))
        cmds = hdr + payload
        dg = self._send_commands(cmds)
        self.unacked[(channel, seq)] = [dg, time.time(), SEND_RELIABLE, cmds]

    def _send_ack(self, channel, recv_seq, sent_time):
        seq = self.sys_seq; self.sys_seq += 1
        b = struct.pack(">BBH", ACKNOWLEDGE, channel & 0xFF, seq)
        b += struct.pack(">HH", recv_seq & 0xFFFF, sent_time & 0xFFFF)
        self._send_commands(bytes(b))

    def ping(self):
        seq = self.sys_seq; self.sys_seq += 1
        b = struct.pack(">BBH", PING | FLAG_ACK, 0xFF, seq)
        dg = self._send_commands(bytes(b))
        self.unacked[(0xFF, seq)] = [dg, time.time(), PING, bytes(b)]
        self.last_ping = time.time()

    def disconnect(self):
        try:
            seq = self.sys_seq; self.sys_seq += 1
            b = struct.pack(">BBH", DISCONNECT | FLAG_ACK, 0xFF, seq)
            self._send_commands(bytes(b))
        except (OSError, ENetError):
            pass
        self.sock.close()

    def _handle_commands(self, body):
        p, n = 0, len(body)
        while p + 4 <= n:
            cmd = body[p] & 0x0F
            needs_ack = bool(body[p] & 0x80)         # ENET_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE
            channel = body[p + 1]
            seq = struct.unpack_from(">H", body, p + 2)[0]
            if cmd == 0:                             # NONE = padding/desync; a 0-size cmd never advances p
                break
            size = CMD_SIZES.get(cmd)
            if self.verbose:
                print("   [cmd] type=%d chan=%d seq=%d%s" % (cmd, channel, seq, " ACK" if needs_ack else ""))
            if size is None:
                if self.verbose:
                    print("   [cmd] unknown cmd byte 0x%02x; stop walk" % body[p])
                return
            # ENet rule: acknowledge EVERY command whose reliable flag (0x80) is set, whatever its type
            # (RELIABLE, FRAGMENT, PING, VERIFY, BANDWIDTH_LIMIT=10, THROTTLE_CONFIGURE=11, ...). Missing
            # this makes the server retransmit then DISCONNECT (that was the in-world drop).
            if needs_ack and cmd != ACKNOWLEDGE:
                self._send_ack(channel, seq, self._cur_sent_time)
            if cmd == SEND_RELIABLE:                  # header(4)+dataLength(2), data at +6 (no extra seq word)
                dl = struct.unpack_from(">H", body, p + 4)[0]
                data = body[p + 6:p + 6 + dl]
                if self.on_message and data:
                    self.on_message(bytes(data))
                p += 6 + dl
            elif cmd == SEND_UNRELIABLE:
                dl = struct.unpack_from(">H", body, p + 6)[0]
                if self.on_message and body[p + 8:p + 8 + dl]:
                    self.on_message(bytes(body[p + 8:p + 8 + dl]))
                p += 8 + dl
            elif cmd == SEND_FRAGMENT:
                dl = struct.unpack_from(">H", body, p + 6)[0]
                start = struct.unpack_from(">H", body, p + 4)[0]
                total = struct.unpack_from(">I", body, p + 16)[0]
                off = struct.unpack_from(">I", body, p + 20)[0]
                f = self.in_frag.setdefault(start, {"total": total, "parts": {}})
                f["parts"][off] = body[p + 24:p + 24 + dl]
                if sum(len(v) for v in f["parts"].values()) >= f["total"]:
                    buf = bytearray(f["total"])
                    for o, d in f["parts"].items():
                        buf[o:o + len(d)] = d
                    del self.in_frag[start]
                    if self.on_message:
                        self.on_message(bytes(buf))
                p += 24 + dl
            elif cmd == VERIFY_CONNECT:
                self.outgoing_peer_id = struct.unpack_from(">H", body, p + 4)[0] & 0x0FFF
                self.out_session = body[p + 7] & 3          # outgoingSessionID from VERIFY
                self.connected = True                        # _build_header now emits the assigned peerID
                for k in [kk for kk, st in self.unacked.items() if st[2] == CONNECT]:
                    del self.unacked[k]                      # CONNECT is acked by VERIFY; stop resending it
                if self.verbose:
                    print("   [verify] assignedPeerID=%d outSess=%d (connected)"
                          % (self.outgoing_peer_id, self.out_session))
                p += size
            elif cmd == ACKNOWLEDGE:
                a_seq = struct.unpack_from(">H", body, p + 4)[0]
                for key in list(self.unacked):
                    if key[1] == a_seq:
                        del self.unacked[key]
                p += size
            elif cmd == DISCONNECT:
                self.connected = False
                raise ENetError("server sent DISCONNECT")
            else:
                p += size

    def _recv_once(self, log=None):
        try:
            data, source = self.sock.recvfrom(4096)
            if source[:2] != self.addr:
                return False
        except proxy.ProxyError as exc:
            raise ENetError(str(exc)) from exc
        except (BlockingIOError, OSError):
            return False
        if log is not None:
            log.append(data)
        self._rx += 1
        if self.verbose:
            print("   [rx #%d] %d bytes: %s" % (self._rx, len(data), data[:40].hex()))
        if len(data) < 6:
            return True
        peer_flags = struct.unpack_from(">H", data, 0)[0]
        pos = 2
        if peer_flags & F_SENT_TIME:
            self._cur_sent_time = struct.unpack_from(">H", data, 2)[0]
            pos += 2
        pos += 4                                  # checksum
        body = data[pos:]
        # Decompress ONLY when the server set the COMPRESSED flag. Many server datagrams (bare ACKs,
        # small commands) are RAW; decompressing those produces garbage that misparses -> we fail to
        # ACK the real reliable commands -> the server retransmits forever and finally DISCONNECTs.
        if peer_flags & F_COMPRESSED:
            dec = _decompress(body)
            if dec:
                body = dec
            elif self.verbose:
                print("   [rx] COMPRESSED flag set but decompress failed (len %d)" % len(body))
        self.last_recv = time.time()
        try:
            self._handle_commands(body)
        except ENetError:
            raise
        except Exception:
            pass
        return True

    def service(self, duration=0.05, log=None):
        end = time.time() + duration
        while True:
            got = self._recv_once(log)
            now = time.time()
            # Liveness: once connected, silence for RECV_TIMEOUT means the peer is gone (a silent drop
            # -- cut internet / server-side timeout -- never delivers a DISCONNECT). Surface it so the
            # supervisor reconnects instead of sitting forever in a dead session.
            if self.connected and now - self.last_recv > RECV_TIMEOUT:
                self.connected = False
                raise ENetError("no data from server for %.0fs (connection lost)" % RECV_TIMEOUT)
            for key, st in list(self.unacked.items()):
                if now - st[1] > RELIABLE_TIMEOUT:
                    try:
                        self.sock.sendto(st[0], self.addr)
                    except OSError:
                        pass                          # network down; the recv-timeout above will fire
                    st[1] = now
            if self.connected and now - self.last_ping > PEER_PING_INTERVAL:
                self.ping()
            if not got and time.time() >= end:
                break
        return self.connected


if __name__ == "__main__":
    import auth
    sd = auth.fetch_server_data()
    host, port = sd["server"], sd["port"]
    if "--replay" in sys.argv:
        # Diagnostic: send the EXACT captured CONNECT bytes verbatim to a current login server.
        # Isolates "does the server reply to a known-good CONNECT at all" from our fresh-packet build.
        real = bytes.fromhex("0dca4f5dd3cdcfffcf9244b29727837b88b1fdf1df576b939eeefcbc0a3e8a642656d33aeb2c10e91da18385")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setblocking(False)
        print("[replay] sending verbatim captured CONNECT to %s:%s" % (host, port))
        s.sendto(real, (host, int(port)))
        t0 = time.time(); got = []
        while time.time() - t0 < 5:
            try:
                d, _ = s.recvfrom(4096); got.append(d)
            except (BlockingIOError, OSError):
                time.sleep(0.1)
        print("[replay] packets received: %d" % len(got))
        for d in got[:3]:
            print("   <-", d[:32].hex())
        s.close()
    else:
        # Fresh CONNECT (our build, fresh connectID). Retry across login-server ports (they vary in
        # responsiveness) until one answers VERIFY_CONNECT.
        for attempt in range(8):
            sd = auth.fetch_server_data()
            host, port = sd["server"], sd["port"]
            c = ENetClient(host, port)
            print("[test %d] CONNECT to %s:%s" % (attempt + 1, host, port))
            c.connect()
            t0 = time.time(); got = []
            while time.time() - t0 < 3 and not c.connected:
                c.service(0.2, log=got)
            print("   packets received: %d  VERIFY_CONNECT: %s" % (len(got), c.connected))
            for d in got[:2]:
                print("   <-", d[:32].hex())
            if c.connected:
                print("[test] CONNECTED (peerID=%d). Holding 2s with pings..." % c.outgoing_peer_id)
                t1 = time.time()
                while time.time() - t1 < 2:
                    c.service(0.2)
                c.disconnect()
                break
            c.disconnect()
            time.sleep(0.5)
