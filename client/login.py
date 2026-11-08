"""Build the Growtopia login packet for the headless client, from the RE in docs/login.md.

Status after the 2026-10-31 ground-truth solve (data/.login_truth.json — real alt capture, no password):
  CONFIRMED against ground truth:
    - Proton HashString = hash_string(s) below.
    - hash2 = signed_decimal(HashString(mac + "RT"))   [matches the real hash2 exactly]
    - Field order = the real 30-field _field_order (see build_fields).
    - rid = uuid4().hex (32 lowercase hex, MachineGuid without dashes); mac = "xx:xx:xx:xx:xx:xx".
    - hash/hash2/fhash are SIGNED int32 decimals (the real hash is negative).
  UNCONFIRMED (self-test FAILs these vs the truth — do NOT trust for a live login yet):
    - klv: STILL UNRESOLVED, but much better understood via native emulation (2026-11-03; see klv_emu.py
      and docs/login.md "klv via emulation"). Two things are now nailed down by Unicorn-emulating the
      real (VM-obfuscated) code:
        (1) inner transform T (FUN_14127f730) = MD5 (UPPERCASE hex), NOT SHA-256 (T("abc")==MD5("abc").upper()).
        (2) FUN_140dcc0c0 (the address the notes called "the klv generator") is NOT the real klv builder:
            its output is a 327-char cleartext concat T("227")+salt3+"5.61"+salt2+T(rid)+salt1+"227"+salt0,
            whereas the real captured klv is 64 hex with NO salts in it, and no hash/HMAC of those
            components reproduces it. The real klv is built by a different, unidentified function.
      So klv() cannot yet be reproduced; it defers to klv_emu.klv (which raises NotImplementedError). The
      old sha256-of-concat hypothesis is obsolete.
    - hash: signed_decimal(HashString(S + "RT")) where S is a device/session string NOT present in the
      truth file (no simple combination of rid/mac/user/wk reproduces it). Input unresolved.
    - fhash: signed_decimal(HashString(concat of other field values)); depends on field values absent from
      the truth file (growid/token/UUIDToken/zf), so it cannot be solved or verified from the truth alone.
Identity is SYNTHETIC (random GUID + MAC in config.json), never the real machine's. Read-only toward the
game; no live traffic here; no password handling beyond placing the user-provided value into the packet."""
import hashlib, json, os, uuid, random

PROTOCOL = "227"          # docs/login.md: _DAT_142218b48 (this build)
GAME_VERSION = "5.61"     # _DAT_141d012ac 0x40b3851f

# klv salts (seed-deobfuscated) - docs/login.md
SALT = [
    "73eff5914c61a20a71ada81a6fc7780700fb1c0285659b4899bc172a24c14fc1",   # salt0
    "3ca373dffbf463bb337e0fd768a2f395b8e417475438916506c721551f32038d",   # salt1
    "c85df9056ee603b849a93e1ebab5dd5f66e1fb8b2f4a8caef8d13b9f9e013fa4",   # salt2
    "e9fc40ec08f9ea6393f59c65e37f750aacddf68490c4f92d0d2523a5bc02ea63",   # salt3
]


def hash_string(s):
    """Proton HashString (FUN_14126bfc0): h=0x55555555; h=(h<<5)+(h>>27)+c; 32-bit wrap."""
    h = 0x55555555
    for c in s.encode("latin1", "replace"):
        h = ((h << 5) + (h >> 27) + c) & 0xFFFFFFFF
    return h


def _signed32(u):
    """GT prints HashString as a SIGNED int32 decimal (confirmed: the real hash is negative)."""
    return u - 0x100000000 if u >= 0x80000000 else u


def hash_string_dec(s):
    return str(_signed32(hash_string(s)))


def T(s):
    """The game's inner transform FUN_14127f730. CONFIRMED by native emulation (klv_emu, 2026-11-03):
    T = MD5, lowercase bytes rendered as UPPERCASE hex. (The earlier SHA-256 guess was wrong.)
    This is used by FUN_140dcc0c0's concat; it is NOT, by itself, the real klv."""
    return hashlib.md5(s.encode("latin1", "replace")).hexdigest().upper()


def klv_concat(rid, protocol=PROTOCOL, game_version=GAME_VERSION):
    """The exact value FUN_140dcc0c0 returns (pure Python, no emulation needed) - the 327-char cleartext
    concat, reconstructed byte-for-byte from the Ghidra decompile (docs/klv_finding_2026-11-03.md):
        T(protocol) + salt3 + game_version + salt2 + T(rid) + salt1 + protocol + salt0
    T = MD5(upper). This is the LEGACY/fallback klv the dump computes; the live client sends a 64-hex
    value from a different (still-unidentified) builder. We send this as the BEST-EFFORT klv for the
    first login attempt - if the server accepts it, we never needed the real one; if it rejects on klv,
    we know the real builder is required (see README 'klv strategy')."""
    return (T(protocol) + SALT[3] + game_version + SALT[2] + T(rid) + SALT[1] + protocol + SALT[0])


def klv(rid, protocol=PROTOCOL, game_version=GAME_VERSION):
    """Real login klv - UNRESOLVED (the live 64-hex builder is unidentified; see
    docs/klv_finding_2026-11-03.md). Defers to klv_emu if present; else raises so callers that demand the
    exact value fail safe. For a login ATTEMPT use klv_concat() (best-effort) or a captured value."""
    try:
        import klv_emu
    except Exception as e:
        raise NotImplementedError("klv unresolved and klv_emu unavailable: %s" % e)
    return klv_emu.klv(rid, protocol, game_version)


def hash2(mac):
    """CONFIRMED against ground truth: hash2 = signed_decimal(HashString(mac + "RT"))."""
    return hash_string_dec(mac + "RT")


def hash_(device_str):
    """UNCONFIRMED: hash = signed_decimal(HashString(S + "RT")). S is a device/session string that is NOT
    in the truth file; input unresolved. Placeholder uses device_str so the shape is right."""
    return hash_string_dec(device_str + "RT")


def fhash(field_values):
    """UNCONFIRMED: fhash = signed_decimal(HashString(concat of other field VALUES)). Depends on fields
    absent from the truth file, so it cannot be verified from the truth alone."""
    return hash_string_dec("".join(field_values))


# ---- synthetic device identity (persisted in config.json; never the real machine's) ----
def _rand_mac():
    return ":".join("%02x" % random.randint(0, 255) for _ in range(6))   # lowercase, like the real capture


def load_config(path):
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    dev = cfg.setdefault("device", {})
    changed = False
    if dev.get("machine_guid", "auto") == "auto":
        dev["machine_guid"] = uuid.uuid4().hex                 # 32 lowercase hex (MachineGuid without dashes)
        changed = True
    if dev.get("mac", "auto") == "auto":
        dev["mac"] = _rand_mac()
        changed = True
    if dev.get("wk", "auto") == "auto":                        # wk: 32 uppercase hex (device key, treated as random)
        dev["wk"] = "".join(random.choice("0123456789ABCDEF") for _ in range(32))
        changed = True
    if changed:                                                # persist so the synthetic "device" stays stable
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    return cfg


# Real captured field order (30) - data/.login_truth.json _field_order (validated 2026-10-31).
FIELD_ORDER = [
    "tankIDName", "tankIDPass", "requestedName", "f", "protocol", "game_version", "fz", "cbits",
    "player_age", "GDPR", "FCMToken", "category", "totalPlaytime", "klv", "hash2", "meta", "fhash",
    "rid", "platformID", "deviceVersion", "country", "hash", "mac", "wk", "zf", "lmode", "user", "token",
    "UUIDToken", "doorID", "aat",
]


def build_ltoken_login(protocol, ltoken):
    """STAGE-1 login to the login server: a minimal ltoken packet (no device fields). The server
    validates the growid web token (ltoken) and replies with OnSendToServer carrying the real
    user/token/UUIDToken for the stage-2 (world-server) login. Confirmed vs CLOEI/Mori build_login_packet."""
    return "protocol|%s\nltoken|%s\nplatformID|2\n" % (protocol, ltoken)


def device_identity(cfg):
    """Return the device-fingerprint fields (rid, mac, klv, hash2, hash, fhash, wk) per cfg identity_mode.

    - "captured": every field comes verbatim from cfg["identity"] - the burner-MachineGuid set the user
      captured once and then changed away from (Plan B). This replays a KNOWN-VALID klv without any RE and
      keeps the main account isolated (the burner guid never coexists with it). fhash depends on the full
      field set, so a captured login must also pin fz/zf/user/token etc. from that same capture.
    - "synthetic" (default): random rid/mac (persisted), klv = best-effort concat, hash2 = confirmed
      formula, hash/fhash best-effort. For the first live test to learn whether the server validates klv.
    """
    mode = cfg.get("identity_mode", "synthetic")
    if mode == "captured":
        ident = cfg["identity"]                                # all values verbatim; user supplies them
        return dict(mode=mode, rid=ident["rid"], mac=ident["mac"], klv=ident["klv"],
                    hash2=ident["hash2"], hash=ident["hash"], fhash=ident.get("fhash"),
                    wk=ident.get("wk", ""))
    dev = cfg["device"]
    rid, mac = dev["machine_guid"], dev["mac"]
    return dict(mode="synthetic", rid=rid, mac=mac, klv=klv_concat(rid), hash2=hash2(mac),
                hash=hash_(mac), fhash=None, wk=dev.get("wk", ""))


def build_fields(cfg, requested_name="", session=None):
    """Build the 30 login fields in the real captured order. Device fields come from device_identity();
    server/session fields (meta, token, user, UUIDToken, fz, wk, doorID, ...) come from `session` - meta
    from server_data.php, the rest from the growid web auth. See auth.py."""
    ident = device_identity(cfg)
    rid, mac = ident["rid"], ident["mac"]
    session = session or cfg.get("session", {})

    vals = {
        "tankIDName": cfg.get("growid", ""),
        "tankIDPass": "",                                      # growid TOKEN login: password is NOT sent
        "requestedName": requested_name,                       #   here (real login has both empty)
        "f": "1",
        "protocol": PROTOCOL,
        "game_version": GAME_VERSION,
        "fz": str(session.get("fz", "0")),
        "cbits": "0",
        "player_age": str(cfg.get("player_age", "13")),
        "GDPR": str(cfg.get("gdpr", "2")),
        "FCMToken": session.get("fcm_token", ""),
        "category": cfg.get("category", "_-5000"),
        "totalPlaytime": "0",
        "klv": ident["klv"],
        "hash2": ident["hash2"],
        "meta": session.get("meta", cfg.get("meta", "")),      # from server_data.php
        "fhash": "",                                           # filled below (unless captured pins it)
        "rid": rid,
        "platformID": cfg.get("platform_id", "0,1,1"),
        "deviceVersion": "0",
        "country": cfg.get("country", "us"),
        "hash": ident["hash"],
        "mac": mac,
        "wk": session.get("wk", ident.get("wk", "")),
        "zf": str(session.get("zf", "0")),
        "lmode": str(session.get("lmode", "1")),               # login mode; from OnSendToServer redirect
        "user": str(session.get("user", "")),
        "token": session.get("token", ""),
        "UUIDToken": session.get("uuid_token", ""),
        "doorID": str(session.get("door_id", "0")),
        "aat": str(session.get("aat", "2")),
    }
    if ident.get("fhash"):                                     # captured mode pins fhash verbatim
        vals["fhash"] = ident["fhash"]
    else:
        vals["fhash"] = fhash([vals[k] for k in FIELD_ORDER if k != "fhash"])  # best-effort
    return [(k, vals[k]) for k in FIELD_ORDER]


def build_login_text(cfg, **kw):
    return "\n".join("%s|%s" % (k, v) for k, v in build_fields(cfg, **kw)) + "\n"


def _self_test():
    """Load the ground-truth capture and assert the reimplementation reproduces each formula from the
    truth's rid/mac. Prints PASS/FAIL booleans ONLY - never rid/mac/klv/hash values."""
    truth_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", ".login_truth.json")
    with open(truth_path, encoding="utf-8") as f:
        t = json.load(f)
    rid, mac = t["rid"], t["mac"]

    try:
        klv_ok = klv(rid) == t["klv"]
    except NotImplementedError:
        klv_ok = False                                        # UNRESOLVED: real klv builder unidentified
    results = {
        "hash2": hash2(mac) == t["hash2"],                    # CONFIRMED - expected PASS
        "klv":   klv_ok,                                      # UNRESOLVED - expected FAIL
        "hash":  hash_(mac) == t["hash"],                     # UNCONFIRMED input - expected FAIL
        "fhash": False,                                       # input fields absent from truth - cannot reproduce
    }
    print("=== login.py self-test vs data/.login_truth.json (booleans only) ===")
    for field in ("klv", "hash", "hash2", "fhash"):
        print("  %-6s %s" % (field, "PASS" if results[field] else "FAIL"))
    print("  (hash2 PASS expected; klv/hash/fhash UNRESOLVED - see module docstring)")
    return results


if __name__ == "__main__":
    _self_test()
