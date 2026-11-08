"""GT Sentry - headless moderation client orchestration.

Flow (reproduced from the real client):
  1. auth.authenticate(cfg)      -> server_data.php (login server + meta) + growid login (session token)
  2. connect to the login/super server (ENet), send the login NetMessage
  3. server replies OnSendToServer (redirect) -> reconnect to the world sub-server, re-login
  4. join the configured world, keepalive, feed received packets to the decoder pipeline

The LIVE login is the gated, ToS-risk step (authorized for the user's OWN alt + OWN world, see memory
gt-headless-moderation-client). It only runs when invoked with --go. Observational only: it sends the
standard login + join + keepalive, never crafted/probe packets. Password is read from config, never logged.
"""
import os, sys, struct, time, json, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "core"))
import login as L
import auth
from enet import ENetClient, ENetError
from gt_decode import parse_variantlist, _kv


def net_message_text(text):
    """NetMessage type 2 (GAME_MESSAGE text): 4-byte LE type + ASCII blob + NUL."""
    return struct.pack("<I", 2) + text.encode("latin1", "replace") + b"\x00"


def net_message_generic_text(text, mtype=3):
    return struct.pack("<I", mtype) + text.encode("latin1", "replace") + b"\x00"


def _pipe_map(s):
    """Parse GT's 'key|value' newline text (e.g. the OnSpawn/OnRemove blob) into a dict."""
    m = {}
    for line in s.replace("\r", "\n").split("\n"):
        k, sep, v = line.partition("|")
        if sep:
            m[k.strip()] = v
    return m


def _strip_gt(s):
    """Strip GT in-text color codes: backtick + one char (`w `o `2 ...) and the `` reset."""
    import re
    return re.sub(r"`.", "", s or "")


# GT "tank" game packet (NetMessage type 4). 56-byte header, all little-endian; extra_data follows.
GAME_PACKET_SIZE = 56
GP_CALL_FUNCTION = 0x01       # extra_data is a VariantList (OnXxx calls)
GP_PING_REQUEST = 0x16        # server anti-AFK ping; must answer with PingReply (0x15) or get kicked
GP_PING_REPLY = 0x15


def _proton(s):
    """GT 'proton' HashString (== GTProxy hash.hpp): used for PingReply's target_net_id."""
    if isinstance(s, str):
        s = s.encode("latin1", "replace")
    h = 0x55555555
    for b in s:
        h = ((h >> 27) + (h << 5) + b) & 0xFFFFFFFF
    return h


class Sentry:
    def __init__(self, cfg):
        self.cfg = cfg
        self.session = None
        self.client = None
        self.world = cfg.get("world", "")
        self.redirect = None                                   # latest dict from OnSendToServer
        self._pending_redirect = False                         # a NEW OnSendToServer to act on (reconnect)
        self.in_world = False
        self.players = {}                                      # netID(str) -> {name, country, userID}
        self.login_result = None                               # "fail" | "banned" (terminal verdicts only)
        self.login_detail = ""                                 # the server text that decided it

    # Server text that means the login did NOT succeed (player-facing messages real clients also see).
    # _retry_plan() then decides the wait or a terminal stop from the detail text.
    FAIL_MARKERS = ("fail to login", "try again", "not correct", "incorrect", "update your game",
                    "unable to validate", "too many", "temporarily", "logon_fail", "login failed",
                    "server overloaded", "overloaded", "maintenance", "exhausted", "update required",
                    "advanced account protection")
    BAN_MARKERS = ("banned", "suspended", "you seem to be", "modified", "third-party", "third party")

    # ---- incoming NetMessage handling ----
    def _on_message(self, payload):
        if len(payload) < 4:
            return
        mtype = struct.unpack_from("<I", payload, 0)[0]
        if mtype in (2, 3):                                     # TEXT / GAME_MESSAGE
            text = payload[4:].split(b"\x00")[0].decode("latin1", "replace")
            self._on_text(text)
        elif mtype == 4 and len(payload) >= 4 + GAME_PACKET_SIZE:   # GAME_PACKET (tank packet)
            self._on_game_packet(payload)

    def _on_game_packet(self, payload):
        """Dispatch a tank packet by its type byte (payload[4]). Only CallFunction + PingRequest matter
        to an observational bot; everything else (movement/tiles/inventory) is ignored."""
        ptype = payload[4]
        if ptype == GP_CALL_FUNCTION:                          # extra_data is a VariantList (OnXxx)
            vs = parse_variantlist(payload, 4 + GAME_PACKET_SIZE)
            if vs and isinstance(vs[0], str):
                self._on_variant(vs)
        elif ptype == GP_PING_REQUEST:                         # answer the server's anti-AFK ping
            challenge = struct.unpack_from("<I", payload, 4 + 20)[0]   # tank 'value' field = challenge
            self._send_ping_reply(challenge)

    def _send_ping_reply(self, challenge):
        """Reply to a game-level PingRequest (keeps us from being kicked on long sessions)."""
        tank = bytearray(GAME_PACKET_SIZE)
        tank[0] = GP_PING_REPLY
        struct.pack_into("<I", tank, 8, _proton(str(challenge)))            # target_net_id = hash(challenge)
        struct.pack_into("<I", tank, 20, int((time.time() - self.client._t0) * 1000) & 0xFFFFFFFF)  # value=ms
        struct.pack_into("<f", tank, 24, 64.0)                              # vector_x = 2 tiles * 32
        struct.pack_into("<f", tank, 28, 64.0)                              # vector_y = 2 tiles * 32
        self.client.send_message(struct.pack("<I", 4) + bytes(tank), channel=0)

    def _on_text(self, text):
        low = text.lower()
        # Classify the login/session outcome from player-facing text (the server tells you plainly).
        if any(m in low for m in self.BAN_MARKERS):
            self.login_result, self.login_detail = "banned", text.strip()
            print("[server]", _strip_gt(text)[:160].replace("\n", " "))
        elif any(m in low for m in self.FAIL_MARKERS):
            self.login_result, self.login_detail = "fail", text.strip()
            print("[server]", _strip_gt(text)[:160].replace("\n", " "))
        elif "re-logon" in low or "re-login" in low:                 # server wants a fresh login
            print("[server] re-logon requested -> reconnecting")
            raise ENetError("server requested re-logon")
        elif self.cfg.get("verbose", False):
            print("[server text]", _strip_gt(text)[:140].replace("\n", " "))  # sfx/misc: only when verbose

    def _on_variant(self, vs):
        fn = vs[0]
        if fn == "OnSendToServer":
            # Confirmed layout (CLOEI/Mori): vs[1]=port, vs[2]=token(int), vs[3]=user(int),
            # vs[4]="host|doorID|uuid", vs[5]=lmode(int), vs[6]=tank_id_name.
            def gi(i, d=0):
                try: return int(vs[i])
                except (IndexError, ValueError, TypeError): return d
            def gs(i, d=""):
                return vs[i] if i < len(vs) and isinstance(vs[i], str) else d
            port = gi(1); token = gi(2); user = gi(3)
            server_str = gs(4); lmode = gi(5, 1); tank = gs(6)
            parts = server_str.split("|")
            host = parts[0].strip() if parts else ""
            door_id = parts[1].strip() if len(parts) > 1 and parts[1].strip() else "0"
            uuid = parts[2].strip() if len(parts) > 2 else ""
            self.redirect = {"host": host, "port": port, "token": str(token), "user": str(user),
                             "door_id": door_id, "uuid": uuid, "lmode": str(lmode), "tank_id_name": tank}
            self._pending_redirect = True                      # reconnect+re-login here (login/gateway/world)
            print("[redirect] OnSendToServer -> %s:%s door=%s user=%s" % (host, port, door_id, user))
        elif fn == "OnTextOverlay":
            print("[server]", _strip_gt(vs[1] if len(vs) > 1 else "")[:120])
        elif fn == "OnRequestWorldSelectMenu":
            print("[server] world-select menu; sending join for %r" % self.world)
            self.join_world(self.world)
        elif fn == "OnFailedToEnterWorld":
            print("[world] failed to enter %r; re-sending join" % self.world)
            self.join_world(self.world)                          # one retry; supervisor recovers if it persists
        elif fn.startswith("OnSuperMainStart"):
            print("[server] accepted logon; sending action|enter_game")
            self._send_text("action|enter_game\n")             # REQUIRED before the world-select/join
        elif fn == "OnSpawn":
            blob = next((v for v in vs[1:] if isinstance(v, str) and "netID|" in v), "")
            m = _pipe_map(blob)
            nid = m.get("netID", ""); name = _strip_gt(m.get("name", "")); country = m.get("country", "")
            if "type" in m:                                    # type|local -> this is us; we're in-world
                self.in_world = True
                print("[world] *** IN WORLD as netID %s (userID %s) ***" % (nid, m.get("userID", "")))
            else:
                self.players[nid] = {"name": name, "country": country, "userID": m.get("userID", "")}
                print("[+ JOIN] %s  (netID %s, %s)" % (name or "?", nid, country))
        elif fn == "OnRemove":
            m = _pipe_map(next((v for v in vs[1:] if isinstance(v, str)), ""))
            nid = m.get("netID", "")
            who = self.players.pop(nid, {}).get("name") or ("netID " + nid)
            print("[- LEAVE] %s" % who)
        elif fn == "OnTalkBubble":
            nid = str(vs[1]) if len(vs) > 1 else ""
            msg = next((v for v in vs[2:] if isinstance(v, str)), "")
            who = self.players.get(nid, {}).get("name") or ("netID " + nid)
            print("[CHAT] %s: %s" % (who, _strip_gt(msg)))
        elif fn == "OnConsoleMessage":
            print("[CHAT/SYS] %s" % _strip_gt(vs[1] if len(vs) > 1 else ""))
        elif self.cfg.get("verbose", False):
            print("[server fn] %s" % fn)                        # other CallFunctions: only when verbose

    # ---- outgoing ----
    def send_stage1_ltoken(self):
        """STAGE 1: minimal ltoken packet to the login server (no device fields). The growid web
        token IS the ltoken; the server replies OnSendToServer with the real world-login creds."""
        ltoken = (self.session or {}).get("token", "")
        text = L.build_ltoken_login(L.PROTOCOL, ltoken)
        self.client.send_message(net_message_text(text), channel=0)
        print("[sentry] stage-1 ltoken login sent (ltoken <%d chars>)" % len(ltoken))

    def send_stage2_redirect(self):
        """STAGE 2: full device field-set to the redirect/world server, using the OnSendToServer creds
        (user/token/UUIDToken/lmode/doorID) + the captured device identity (klv/rid/hash/mac/wk) + meta."""
        r = self.redirect or {}
        sess = dict(self.session or {})
        sess.update({"user": r.get("user", ""), "token": r.get("token", ""),
                     "uuid_token": r.get("uuid", ""), "door_id": r.get("door_id", "0"),
                     "lmode": r.get("lmode", "1")})
        text = L.build_login_text(self.cfg, requested_name=r.get("tank_id_name", ""), session=sess)
        self.client.send_message(net_message_text(text), channel=0)
        print("[sentry] stage-2 redirect login sent (identity=%s, door=%s)"
              % (self.cfg.get("identity_mode", "synthetic"), r.get("door_id", "0")))

    def _send_text(self, text):
        """Send a GT GENERIC_TEXT NetMessage (type 2) reliably on channel 0 (e.g. action|enter_game)."""
        self.client.send_message(net_message_text(text), channel=0)

    def _send_game_message(self, text):
        """Send a GT GAME_MESSAGE NetMessage (type 3) reliably on channel 0 (in-game actions: join, etc.)."""
        self.client.send_message(net_message_generic_text(text, 3), channel=0)

    def join_world(self, name):
        # World join is a GAME_MESSAGE (type 3), not GENERIC_TEXT -- confirmed vs CLOEI/Mori `warp`.
        self._send_game_message("action|join_request\nname|%s|\ninvitedWorld|0\n" % name)

    # ---- connect ----
    def _connect(self, host, port):
        if self.client:
            self.client.disconnect()
        self.client = ENetClient(host, port)
        self.client.on_message = self._on_message
        self.client.connect()
        t0 = time.time()
        while not self.client.connected and time.time() - t0 < 5:
            self.client.service(0.1)
        return self.client.connected

    def _connect_retry(self, host, port, attempts=6, refresh_discovery=True):
        """Login-server ports vary in responsiveness; retry, re-fetching server_data for a fresh port."""
        for i in range(attempts):
            if self._connect(host, port):
                print("[enet] connected to %s:%s (peerID=%d)" % (host, port, self.client.outgoing_peer_id))
                return True
            print("[enet] no VERIFY from %s:%s, retrying (%d/%d)" % (host, port, i + 1, attempts))
            time.sleep(2.0)
            if not refresh_discovery:
                continue  # redirected credentials belong to this endpoint, not a fresh login server
            try:
                sd = auth.fetch_server_data()
                host, port = sd.get("server", host), sd.get("port", port)
            except Exception as e:
                print("[enet] server_data refetch failed (%s); reusing port" % e)
        return False

    # Signals that the failure was the network being down (offline / DNS) rather than a server decision.
    NET_ERRORS = ("getaddrinfo", "unreachable", "timed out", "timeout", "temporarily",
                  "connection", "11001", "failed to establish", "name or service", "no address")
    # Known server login-system messages -> how long to wait (mirrors CLOEI/Mori's account handling).
    STOP_MARKERS = ("exhausted", "update required", "advanced account protection")  # don't auto-retry

    def _retry_plan(self, outcome, detail, backoff, lo, hi, net_wait):
        """Return (wait_seconds, new_backoff, stop, reason) for a failed/ended session."""
        low = (detail or "").lower()
        if outcome == "banned" or any(m in low for m in self.STOP_MARKERS):
            return (0, backoff, True, "terminal: %s" % detail[:80])
        if outcome in ("auth_fail", "connect_fail", "error") and any(k in low for k in self.NET_ERRORS):
            return (net_wait, lo, False, "network error (%s)" % (detail[:100] or "?"))  # retry fast, no growth
        if outcome == "in_world_dropped":
            return (lo, lo, False, "world connection dropped")                   # good session -> reset backoff
        if outcome == "login_fail":
            if "too many" in low:      w = 5
            elif "overloaded" in low:  w = 30
            elif "maintenance" in low: w = 600
            else:                      w = backoff                               # generic 'try again' -> backoff
            return (w, min(backoff * 2, hi), False, "login refused: %s" % detail[:70])
        return (backoff, min(backoff * 2, hi), False, "session ended (%s)" % outcome)

    def run(self):
        """24/7 supervisor: run a session; on any recoverable drop, re-auth and reconnect. Network outages
        retry fast (fixed interval); login cooldowns back off; a few terminal messages stop. Mirrors Mori's
        account handling. Stops only on Ctrl-C or a terminal verdict (never auto-retries a flagged account)."""
        lo = int(self.cfg.get("reconnect_min_s", 15))
        hi = int(self.cfg.get("reconnect_max_s", 300))
        net_wait = int(self.cfg.get("network_retry_s", 5))
        backoff = lo
        while True:
            try:
                outcome, detail = self._run_once()
            except KeyboardInterrupt:
                print("\n[sentry] stopping (user)"); self._cleanup(); return
            except Exception as e:                              # auth/network blip -> treat as recoverable
                outcome, detail = "error", str(e)
            finally:
                self._cleanup()
            wait, backoff, stop, reason = self._retry_plan(outcome, detail, backoff, lo, hi, net_wait)
            if stop:
                print("[sentry] STOP -- %s. Not auto-reconnecting." % reason); self._cleanup(); return
            print("[sentry] %s -> retry in %ds (Ctrl-C to stop)" % (reason, wait))
            try:
                time.sleep(wait)
            except KeyboardInterrupt:
                print("\n[sentry] stopping (user)"); self._cleanup(); return

    def _run_once(self):
        """One full session: auth -> login server -> redirect chain -> world join -> in-world loop.
        Returns (outcome, detail). outcome in: in_world_dropped, login_fail, banned, connect_fail,
        auth_fail, stalled. Raises KeyboardInterrupt up to run() for a clean stop."""
        # reset per-attempt state
        self.redirect = None; self._pending_redirect = False; self.in_world = False
        self.players = {}; self.login_result = None; self.login_detail = ""
        vb = bool(self.cfg.get("verbose", False))

        print("[sentry] authenticating (growid HTTPS)...")
        try:
            self.session = auth.authenticate(self.cfg)
        except Exception as e:
            return ("auth_fail", str(e)[:120])
        sd = self.session.get("_server_data", {})
        host, port = sd.get("server"), sd.get("port", "17091")
        print("[sentry] login server %s:%s  meta=%s" % (host, port, "set" if self.session.get("meta") else "none"))
        if not self._connect_retry(host, port, attempts=4):
            return ("connect_fail", "login server")
        self.client.verbose = vb

        # First login = ltoken to the login server; then follow the OnSendToServer redirect CHAIN
        # (login server -> gateway -> world sub-server), re-logging-in at each hop, until OnSpawn.
        self.send_stage1_ltoken()
        hops = 0
        while True:
            self._pending_redirect = False
            self._await_event(25)
            if self.login_result == "fail":
                self._print_fail("hop %d" % hops); self._cleanup(); return ("login_fail", self.login_detail[:80])
            if self.login_result == "banned":
                self._cleanup(); return ("banned", self.login_detail[:80])
            if self.in_world:
                break
            if self._pending_redirect and self.redirect:
                hops += 1
                print("[sentry] following redirect (hop %d) -> %s:%s"
                      % (hops, self.redirect["host"], self.redirect["port"]))
                if not self._connect_retry(self.redirect["host"], self.redirect["port"], attempts=4,
                                           refresh_discovery=False):
                    self._cleanup(); return ("connect_fail", "redirect hop %d" % hops)
                self.client.verbose = vb
                self.send_stage2_redirect()
                continue
            self._cleanup(); return ("stalled", "no redirect/OnSpawn in 25s")

        print("\n================ IN WORLD ================")
        print("RESULT: *** IN WORLD *** (%s, identity=%s). Watching chat/joins (Ctrl-C to stop)."
              % (self.world, self.cfg.get("identity_mode", "synthetic")))
        print("==========================================")
        try:
            while True:
                self.client.service(0.2)
        except ENetError as e:
            self._cleanup(); return ("in_world_dropped", str(e)[:80])
        except KeyboardInterrupt:
            self._cleanup(); raise

    def _await_event(self, secs):
        """Service until a redirect / in-world / terminal verdict occurs, or `secs` elapse."""
        deadline = time.time() + secs
        while time.time() < deadline and not (
                self._pending_redirect or self.in_world or self.login_result in ("fail", "banned")):
            self.client.service(0.1)

    def _cleanup(self):
        if self.client:
            self.client.disconnect()
            self.client = None

    def _print_fail(self, stage):
        print("\n================ LOGIN VERDICT ================")
        print("RESULT: REJECTED at %s (not a ban)." % stage)
        print("  server said: %s" % self.login_detail[:160].replace("\n", " "))
        print("  The login was parsed but refused. If this is 'Fail to login/try again', it is often a")
        print("  login cooldown from repeated attempts -- wait several minutes with NO connects, then ONE")
        print("  --go. If it persists clean, the ltoken/token mapping for this stage needs adjusting.")
        print("==============================================")


def main():
    ap = argparse.ArgumentParser(description="GT Sentry headless client")
    ap.add_argument("--config", default=os.path.join(HERE, "config.json"))
    ap.add_argument("--go", action="store_true", help="actually perform the LIVE login (gated)")
    ap.add_argument("--dry", action="store_true", help="build the login text and print its shape, no network")
    ap.add_argument("--proxy", help="SOCKS5 endpoint host:port; overrides config proxy, no direct fallback")
    ap.add_argument("--check", action="store_true",
                    help="connectivity test from THIS host/IP: server_data + UDP handshake, NO account login")
    args = ap.parse_args()
    cfg = L.load_config(args.config)
    if args.proxy:
        import proxy_transport
        cfg["proxy"] = proxy_transport.parse_endpoint(args.proxy)
    if args.dry:
        text = L.build_login_text(cfg, requested_name="")
        ident = L.device_identity(cfg)
        print("identity_mode:", ident["mode"])
        for line in text.split("\n"):
            k = line.split("|", 1)[0]
            if k in ("tankIDPass", "klv", "rid", "mac", "hash", "hash2", "fhash", "wk", "token", "meta"):
                print("  %-14s <%d chars>" % (k, len(line.split("|", 1)[1]) if "|" in line else 0))
            elif k:
                print("  %s" % line)
        return
    import proxy_transport as proxy
    if args.go or args.check:
        proxy.configure(cfg.get("proxy"))
    if (cfg.get("netguard", True) or proxy.enabled()) and (args.go or args.check):
        import netguard
        hosts = tuple(cfg.get("netguard_hosts", netguard.DEFAULT_HOSTS))
        cidrs = tuple(cfg.get("netguard_cidrs", netguard.DEFAULT_CIDRS))
        h, n = netguard.install(hosts, cidrs)
        if proxy.enabled():
            netguard.lock_to_proxy(proxy.endpoint())
            print("[netguard] proxy-only egress via %s:%s; direct fallback disabled" % proxy.endpoint())
        else:
            print("[netguard] egress locked to Growtopia only: hosts=%s nets=%s" % (h, n))

    if args.check:                                              # reachability test, no account login
        print("[check] fetching server_data over HTTPS (www.growtopia1.com)...")
        try:
            sd = auth.fetch_server_data()
        except Exception as e:
            import traceback
            print("[check] server_data FAILED: %r" % e)
            print("        -> if this is a timeout/getaddrinfo, this host can't reach Growtopia's HTTPS")
            print("           (datacenter IP blocked by Cloudflare, or no outbound 443). Full error:")
            traceback.print_exc()
            return
        host, port = sd.get("server"), int(sd.get("port", "17091"))
        print("[check] server_data OK -> game server %s:%s (meta=%s)"
              % (host, port, "set" if sd.get("meta") else "none"))
        print("[check] UDP ENet handshake to %s:%s ..." % (host, port))
        c = ENetClient(host, port)
        c.connect()
        t0 = time.time()
        while not c.connected and time.time() - t0 < 6:
            c.service(0.2)
        print("[check] RESULT: %s" % ("*** REACHABLE *** (VERIFY_CONNECT from this IP)" if c.connected
                                      else "no VERIFY_CONNECT (UDP blocked here, or server busy -- retry)"))
        c.disconnect()
        return

    if not args.go:
        print("Refusing to connect without --go (the live login is the gated step). "
              "Use --check for a no-login connectivity test, or --dry to inspect.")
        return
    Sentry(cfg).run()


if __name__ == "__main__":
    main()
