#!/usr/bin/env python3
"""Growtopia ENet -> chat decoder (validated against a real capture).

Pipeline per UDP datagram:
  ENet header (peerID[2] + optional sentTime[2] + checksum[4])
    -> if COMPRESSED flag: range-coder decompress (pure-Python core/rangecoder, portable; no native DLL)
    -> ENet command stream -> reliable/fragment reassembly
    -> application packets (NetMessage); type 4 = GAME_PACKET
    -> VariantList at offset 60 (NetMessage u32 + 56-byte GameUpdatePacket)
    -> OnConsoleMessage / OnTalkBubble / OnSpawn / join_request

Exposes ChatDecoder: feed(direction, payload, t) -> list of events.
"""
import collections, os, struct, re

HERE = os.path.dirname(os.path.abspath(__file__))
import sys as _sys
_sys.path.insert(0, HERE)
from rangecoder import decompress as _rc_decompress   # pure-Python ENet decoder (validated vs rc.dll)

def _decompress(body: bytes) -> bytes:
    try:
        return _rc_decompress(body)
    except Exception:
        return b""

# ENet command ids
C_ACK=1; C_CONNECT=2; C_VERIFY=3; C_DISCONNECT=4; C_PING=5
C_RELIABLE=6; C_UNRELIABLE=7; C_FRAGMENT=8; C_UNSEQ=9
C_BWLIMIT=10; C_THROTTLE=11; C_UNREL_FRAGMENT=12
CMD_MASK=0x0F
# fixed header size per command (bytes before any payload)
FIXED={C_ACK:8,C_CONNECT:48,C_VERIFY:44,C_DISCONNECT:8,C_PING:4,
       C_RELIABLE:6,C_UNRELIABLE:8,C_FRAGMENT:24,C_UNSEQ:8,
       C_BWLIMIT:12,C_THROTTLE:16,C_UNREL_FRAGMENT:24}

def strip_color(s: str) -> str:
    # GT color codes: backtick + one char ( `w `4 `$ ... ), `` resets. Remove all.
    return re.sub(r"`.", "", s)

def _walk_commands(body):
    """Yield (ctype, channel, reliableSeq, data, frag) for every ENet command in a
    decoded body. Every command header is [command, channelID, reliableSeq(2)];
    CONNECT / VERIFY_CONNECT are yielded too (data None) so callers can see new
    connections."""
    p, n = 0, len(body)
    while p + 4 <= n:
        cmd = body[p]; ctype = cmd & CMD_MASK
        if ctype not in FIXED:
            return
        base = FIXED[ctype]
        chan = body[p + 1]
        rseq = struct.unpack_from(">H", body, p + 2)[0]
        if ctype in (C_RELIABLE,):
            if p + 6 > n: return
            dlen = struct.unpack_from(">H", body, p + 4)[0]
            yield (ctype, chan, rseq, body[p+6:p+6+dlen], None)
            p += 6 + dlen
        elif ctype in (C_UNRELIABLE, C_UNSEQ):
            if p + 8 > n: return
            dlen = struct.unpack_from(">H", body, p + 6)[0]
            yield (ctype, chan, rseq, body[p+base:p+base+dlen], None)
            p += base + dlen
        elif ctype in (C_FRAGMENT, C_UNREL_FRAGMENT):
            if p + 24 > n: return
            startSeq=struct.unpack_from(">H",body,p+4)[0]
            dlen=struct.unpack_from(">H",body,p+6)[0]
            fragCount=struct.unpack_from(">I",body,p+8)[0]
            fragNum=struct.unpack_from(">I",body,p+12)[0]
            totalLen=struct.unpack_from(">I",body,p+16)[0]
            fragOff=struct.unpack_from(">I",body,p+20)[0]
            yield (ctype, chan, rseq, body[p+24:p+24+dlen],
                   dict(start=startSeq,count=fragCount,num=fragNum,total=totalLen,off=fragOff))
            p += 24 + dlen
        else:
            if ctype in (C_CONNECT, C_VERIFY):
                yield (ctype, chan, rseq, None, None)
            p += base

# Variant types
VT_FLOAT=1;VT_STRING=2;VT_VEC2=3;VT_VEC3=4;VT_UINT=5;VT_INT=9
def parse_variantlist(d, off=60):
    if off >= len(d): return []
    count=d[off]; p=off+1; vals=[]
    for _ in range(count):
        if p+2>len(d): break
        vt=d[p+1]; p+=2
        if vt==VT_STRING:
            if p+4>len(d): break
            ln=struct.unpack_from("<I",d,p)[0]; p+=4
            vals.append(d[p:p+ln].decode("latin1")); p+=ln
        elif vt in (VT_INT,VT_UINT):
            vals.append(struct.unpack_from("<i" if vt==VT_INT else "<I",d,p)[0]); p+=4
        elif vt==VT_FLOAT:
            vals.append(struct.unpack_from("<f",d,p)[0]); p+=4
        elif vt==VT_VEC2:
            vals.append(struct.unpack_from("<ff",d,p)); p+=8
        elif vt==VT_VEC3:
            vals.append(struct.unpack_from("<fff",d,p)); p+=12
        else:
            break
    return vals

def _kv(blob):
    d={}
    for line in blob.split("\n"):
        if "|" in line:
            k,_,v=line.partition("|"); d[k]=v
    return d

class RepeatTracker:
    """Repetition-based spam detector (content-agnostic). Keyed on the
    color-stripped, lowercased text; when the same text recurs `threshold` times
    within `window` seconds it is flagged. Intended for /me emotes only (trade
    bots spam identical/rotating ads via /me), so normal chat is never affected.
    """
    def __init__(self, window=180.0, threshold=2):
        self.window = window
        self.threshold = threshold
        self._hist = {}   # normalized text -> list[timestamps]

    @staticmethod
    def _norm(text):
        return re.sub(r"\s+", " ", strip_color(text or "").lower()).strip()

    def check(self, text, t):
        """Record `text` at time `t`; return True if it now counts as repeated."""
        norm = self._norm(text)
        if not norm:
            return False
        lst = self._hist.setdefault(norm, [])
        lst[:] = [x for x in lst if t - x <= self.window]   # prune old
        lst.append(t)
        if len(self._hist) > 4000:                          # bound memory
            self._hist = {k: v for k, v in self._hist.items() if v and t - v[-1] <= self.window}
        return len(lst) >= self.threshold

# Raw OnConsoleMessage formats (color codes intact):
#   chat : "CP:.._CT:[W]_ `6<`wRemuen``>`` `$`$bu 100tllik paketi````"
#   emote: "CP:.._CT:[W]_ `6<```wNAME`` `#`4ACTION```6>``"   (`>` only at the end)
_CT_RE = re.compile(r"CT:\[(?P<ch>[^\]]*)\]_\s*(?P<body>.*)$", re.S)
# name = first color-wrapped token after "<": optional resets, `X color, NAME, ``
_NAME_RE = re.compile(r"<(?:``)*`.(?P<name>[^`]+)``(?P<after>.*)$", re.S)
_WORLD_RE = re.compile(r"^World (\S+?)(?:\s+\[.*?\])?\s+entered\b")

def clean_message(s):
    """Remove game framing (leading `$/`# default-color codes, resets, spaces;
    trailing resets/dangling codes) while PRESERVING user color codes (`8 `4 `w)."""
    s = s.strip()
    s = re.sub(r"^(?:\s|`[$#]|``)+", "", s)   # leading framing
    s = re.sub(r"(?:`.)+$", "", s)            # trailing resets / dangling codes
    return s.strip()

def clean_emote_action(s):
    """Emote action: strip the trailing `<color>>`` bracket structure + leading
    framing, keep inner user colors."""
    s = re.sub(r"(?:`.|>|\s)+$", "", s)       # trailing bracket color/>/space
    s = re.sub(r"^(?:\s|`[$#]|``)+", "", s)   # leading framing
    return s.strip()

_MUMBLE_RE = re.compile(r"[fmFM\s.,!?'~-]+")

def is_mumbled(text):
    """Grumbleteeth chat: every letter turned into f/m (spaces, case kept), e.g.
    "mmmmffmmm fmmmmmmm". The server sends it like that - the original letters are
    not in the packet, so other players' mumbled text can't be turned back."""
    s = strip_color(text or "").strip()
    letters = re.sub(r"[^A-Za-z]", "", s)
    return len(letters) >= 3 and set(letters.lower()) <= {"f", "m"} and bool(_MUMBLE_RE.fullmatch(s))

def _shape(s):
    """Letters per word - kept by the mumbling."""
    out = []
    for w in strip_color(s or "").split():
        k = len(re.sub(r"[^\w]", "", w))
        if k:
            out.append(k)
    return tuple(out)

class MumbleTracker:
    """Pairs YOUR mumbled chat (echoed back by the server as f/m) with the text you
    actually typed, which the logger sees in your outgoing input packet."""
    def __init__(self, window=10.0):
        self.window = window
        self.recent = []          # [(t, typed text)]

    def typed(self, text, t):
        if text and not text.startswith("/"):
            self.recent.append((t, text))
            self.recent = self.recent[-20:]

    def clear_for(self, name, local_name, mumbled, t):
        self.recent = [(tt, x) for tt, x in self.recent if t - tt <= self.window]
        if not self.recent:
            return None
        mine = bool(local_name) and name.lower() == local_name.lower()
        if local_name and not mine:
            return None
        shape = _shape(mumbled)
        cands = [c for c in self.recent if _shape(c[1]) == shape]
        if not cands and mine:
            cands = self.recent[:]             # shape differs (e.g. punctuation): latest line you typed
        if not mine:                           # your name unknown yet: only a fresh, exact-shape match
            cands = [c for c in cands if t - c[0] <= 3.0]
        if not cands:
            return None
        best = cands[-1]
        self.recent.remove(best)
        return best[1]

class ChatDecoder:
    def __init__(self):
        self.roster = {}          # netID(str) -> name(clean)
        self.world = None
        self.local_name = None    # your own name (from your OnSpawn, type|local)
        self.duplicates = 0       # retransmitted ENet commands dropped
        self._frag = {}           # (dir,start) -> {total,parts}
        self._seen = {}           # (dir, stream, peer/session, channel) -> (set, deque) of reliable seqs

    # ENet resends a reliable command when its ACK is late or lost; the game drops the
    # second copy by its reliable sequence number, so must we (else chat is logged twice).
    def _is_dup(self, key, seq):
        s = self._seen.get(key)
        if s is None:
            s = self._seen[key] = (set(), collections.deque())
        seen, order = s
        if seq in seen:
            return True
        seen.add(seq); order.append(seq)
        if len(order) > 4096:                # sequence numbers wrap at 65536
            seen.discard(order.popleft())
        return False

    def _reset_stream(self, stream):
        for k in [k for k in self._seen if k[1] == stream]:
            del self._seen[k]

    def _maybe_world(self, clean_text, t, ev):
        """If `clean_text` is a 'World X entered' line, update the current world."""
        mw = _WORLD_RE.match(clean_text)
        if mw:
            self.world = mw.group(1)

    def _reassemble(self, direction, ctype, seq, data, frag):
        if frag is None:
            return [data]
        key = (direction, frag["start"])
        f = self._frag.setdefault(key, {"total": frag["total"], "parts": {}})
        f["parts"][frag["off"]] = data
        if sum(len(v) for v in f["parts"].values()) >= f["total"]:
            buf = bytearray(f["total"])
            for off, d in f["parts"].items():
                buf[off:off+len(d)] = d
            del self._frag[key]
            return [bytes(buf)]
        return []

    def feed(self, direction, payload, t, stream=None):
        """direction: 'S' (server->client) or 'C' (client->server); stream: the
        server endpoint ("ip:port"), so retransmits are recognised per connection.
        Returns events."""
        events = []
        if len(payload) < 6:
            return events
        peer = (payload[0] << 8) | payload[1]
        pos = 2 + (2 if peer & 0x8000 else 0) + 4   # peer + optional sentTime + checksum
        body = payload[pos:]
        if peer & 0x4000:
            body = _decompress(body)
            if not body:
                return events
        conn = peer & 0x3FFF                         # session bits + peer id
        for ctype, chan, rseq, data, frag in _walk_commands(body):
            if ctype in (C_CONNECT, C_VERIFY):       # new connection: sequence numbers restart
                self._reset_stream(stream)
                continue
            if ctype not in (C_RELIABLE, C_FRAGMENT, C_UNRELIABLE, C_UNREL_FRAGMENT, C_UNSEQ):
                continue
            if ctype in (C_RELIABLE, C_FRAGMENT) and self._is_dup((direction, stream, conn, chan), rseq):
                self.duplicates += 1
                continue
            seq = frag["start"] if frag else rseq
            for pkt in self._reassemble(direction, ctype, seq, data, frag):
                events += self._handle_app(direction, pkt, t)
        return events

    def _handle_app(self, direction, pkt, t):
        ev = []
        if len(pkt) < 4:
            return ev
        mtype = struct.unpack_from("<I", pkt, 0)[0]
        # NetMessage type 2/3 are text GameMessages (both directions).
        if mtype in (2, 3):
            try:
                txt = pkt[4:].split(b"\x00")[0].decode("latin1")
            except Exception:
                txt = ""
            if direction == "C":
                info = _kv(txt)
                if info.get("action") == "join_request" and "name" in info:
                    self.world = info["name"]
                    ev.append(dict(t=t, kind="world_enter", world=self.world))
                # your own typed chat / "/" commands: action|input ... text|<...>
                m = re.search(r"text\|(.+)", txt)
                if m and m.group(1).strip():
                    typed = m.group(1).strip()
                    ev.append(dict(t=t, kind="self", world=self.world,
                                   message=clean_message(typed),
                                   is_cmd=typed.startswith("/"), raw=txt))
            else:
                # server console text (e.g. /who, /msg replies, notices) arrives
                # as "action|log \n msg|<text>".
                if "action|log" in txt:
                    m = re.search(r"msg\|(.*)", txt, re.S)
                    if m:
                        craw = m.group(1).rstrip("\n")
                        # server log messages end with a `` reset; drop a short
                        # trailing framing byte after it (packets aren't always
                        # NUL-terminated, so a stray byte can tag along).
                        idx = craw.rfind("``")
                        if idx != -1 and len(craw) - (idx + 2) <= 3:
                            craw = craw[:idx + 2]
                        clean = strip_color(craw).strip()
                        clean = re.sub(r"^CT:\[[^\]]*\]_\s*", "", clean)  # drop echo prefix
                        self._maybe_world(clean, t, ev)
                        ev.append(dict(t=t, kind="system", world=self.world,
                                       message=clean, raw=craw))
            return ev
        if mtype != 4 or len(pkt) < 61:
            return ev
        vs = parse_variantlist(pkt, 60)
        if not vs:
            return ev
        fn = vs[0] if isinstance(vs[0], str) else ""
        if fn == "OnSpawn" and len(vs) >= 2 and isinstance(vs[1], str):
            info = _kv(vs[1])
            if "netID" in info and "name" in info:
                self.roster[info["netID"]] = strip_color(info["name"])
            # local avatar spawn: your own name (and maybe the world name)
            if info.get("type") == "local":
                if "name" in info:
                    self.local_name = strip_color(info["name"]).strip()
                if info.get("world"):
                    self.world = info["world"]
        elif fn == "OnConsoleMessage" and len(vs) >= 2 and isinstance(vs[1], str):
            raw = vs[1]
            mct = _CT_RE.search(raw)
            mn = _NAME_RE.search(mct.group("body")) if mct else None
            if mct and mn:
                ch = mct.group("ch"); name = mn.group("name").strip()
                after = mn.group("after")
                a = after.lstrip()
                if a.startswith(">"):
                    # normal chat: message follows the name bracket
                    ev.append(dict(t=t, kind="chat", world=self.world, channel=ch,
                                   name=name, message=clean_message(a[1:]), raw=raw))
                else:
                    # /me emote: name + action live inside the brackets
                    ev.append(dict(t=t, kind="emote", world=self.world, channel=ch,
                                   name=name, message=clean_emote_action(after), raw=raw))
            else:
                cl = strip_color(raw).strip()
                # "World X [..]  entered." or "World X entered." -> current world
                self._maybe_world(cl, t, ev)
                ev.append(dict(t=t, kind="system", world=self.world,
                               message=cl, raw=raw))
        elif fn == "OnTalkBubble" and len(vs) >= 3:
            nid = str(vs[1]); msg = vs[2] if isinstance(vs[2], str) else ""
            # message often "CP:.._player_chat=<msg>" or "CP:.._OID:_<msg>"
            cm = strip_color(msg)
            after = cm.split("player_chat=", 1)
            text = after[1] if len(after) > 1 else re.sub(r"^CP:[^_]*_PL:[^_]*_OID:_?", "", cm)
            ev.append(dict(t=t, kind="bubble", world=self.world, netID=nid,
                           name=self.roster.get(nid, f"netID:{nid}"),
                           message=text.strip(), raw=msg))
        return ev
