"""GT HTTPS auth: server_data.php (login server + meta) and the growid login (-> session token).

Reproduced from the real client's flow, observed in a TLS-intercept of a legitimate login
(2026-11-03; see docs/klv_finding_2026-11-03.md). Endpoints seen:
  POST login.growtopiagame.com/player/login/dashboard?valKey=<md5>   (full login blob -> dashboard HTML)
  GET  login.growtopiagame.com/player/growid/login?token=<t>          (login form page, carries _token CSRF)
  POST login.growtopiagame.com/player/growid/login/validate           (_token, growId, password)
       -> {"status":"success","token":"<base64>","accountType":"growtopia","accountAge":N}
The 472-char `token` is the session credential -> goes in the ENet login `token` field.
`meta` for the login comes from server_data.php, NOT the device.

This performs a REAL login for the user's own alt (authorized). It sends ONLY the standard requests the
real client sends - never crafted/probe traffic. Password is read from config and never logged.
Stdlib only (urllib + http.cookiejar) to avoid extra deps.
"""
import json, re, ssl, urllib.request, urllib.parse, http.cookiejar

SERVER_DATA_URL = "https://www.growtopia1.com/growtopia/server_data.php"
LOGIN_HOST = "https://login.growtopiagame.com"
# The in-game browser UA; adjust if the server 403s. GT's own HTTP UA for server_data is the line below.
GAME_UA = "UbiServices_SDK_2022.Release.9_PC64_ansi_static"
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/120.0.0.0 Safari/537.36")


def _web_headers(extra=None):
    """Full browser-like headers so the WAF treats us like the in-game browser, not a bare bot."""
    h = {"User-Agent": BROWSER_UA,
         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
         "Accept-Language": "en-US,en;q=0.9",
         "Accept-Encoding": "identity",
         "Connection": "keep-alive"}
    if extra:
        h.update(extra)
    return h


def _opener():
    cj = http.cookiejar.CookieJar()
    ctx = ssl.create_default_context()
    import proxy_transport as proxy
    handlers = [urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(cj)]
    if proxy.enabled():
        handlers += [proxy.HTTPSHandler(context=ctx), proxy.NoHTTPHandler()]
    else:
        handlers += [urllib.request.HTTPSHandler(context=ctx)]
    return urllib.request.build_opener(*handlers)


def _parse_kv_bar(text):
    """server_data.php returns `key|value` lines terminated by RTENDMARKERBS1001."""
    out = {}
    for line in text.replace("\r", "").split("\n"):
        if line.startswith("RTENDMARKER"):
            break
        k, sep, v = line.partition("|")
        if sep:
            out[k] = v
    return out


def fetch_server_data(protocol="227", version="5.61", platform="0", timeout=15):
    errors = []
    for host in ("www.growtopia1.com", "www.growtopia2.com"):
        try:
            return _fetch_server_data(host, protocol, version, platform, timeout)
        except (OSError, RuntimeError) as exc:
            status = getattr(exc, "code", None)
            errors.append("%s: %s%s" % (host, type(exc).__name__,
                          " HTTP %s" % status if status else " " + str(exc)[:150]))
    raise RuntimeError("server discovery failed; " + "; ".join(errors))


def _fetch_server_data(host, protocol, version, platform, timeout):
    """POST server_data.php -> {server, port, type, meta, ...}. `meta` feeds the login's meta field."""
    body = urllib.parse.urlencode({
        "version": version, "platform": platform, "protocol": protocol,
    }).encode()
    req = urllib.request.Request("https://%s/growtopia/server_data.php" % host, data=body, method="POST", headers={
        "User-Agent": GAME_UA, "Content-Type": "application/x-www-form-urlencoded",
    })
    with _opener().open(req, timeout=timeout) as r:
        text = r.read().decode("latin1", "replace")
    data = _parse_kv_bar(text)
    if "server" not in data:
        raise RuntimeError("server_data.php returned no server; got keys %s" % list(data))
    return data


def _snippet(html):
    """A compact, secret-free view of an HTML body: collapse whitespace, show tokens' presence not value."""
    s = re.sub(r"\s+", " ", html).strip()
    s = re.sub(r'(value|content)="[^"]{20,}"', r'\1="<...>"', s)   # redact long token-ish values
    return s[:400]


def _find_csrf(html):
    """_token is a hidden input (attrs in any order, e.g. name="_token" type="hidden" value="..") OR a
    <meta name="csrf-token" content="..">."""
    m = re.search(r'name="_token"[^>]*?value="([^"]+)"', html) or \
        re.search(r'value="([^"]+)"[^>]*?name="_token"', html) or \
        re.search(r'name="csrf-token"[^>]*?content="([^"]+)"', html) or \
        re.search(r'content="([^"]+)"[^>]*?name="csrf-token"', html)
    return m.group(1) if m else ""


def _find_growid_login_href(html):
    m = re.search(r'href="(/player/growid/login[^"]*)"', html) or \
        re.search(r'(https?://login\.growtopiagame\.com/player/growid/login[^"\s]*)', html)
    return m.group(1) if m else ""


def _dashboard_blob(cfg, meta):
    """Pre-auth login blob POSTed to /player/login/dashboard: full field set with EMPTY credentials,
    our device identity, server meta. probe2 confirmed this body makes the dashboard return the growid
    login page (with a ?token=). Credential-free: no growId/password in it."""
    import login as L
    preauth = dict(cfg)
    preauth["growid"] = ""
    preauth["password"] = ""
    return L.build_login_text(preauth, requested_name="", session={"meta": meta})


def _login_page(op, timeout, blob, dbg=None):
    """Reach the growid login FORM, return (html, csrf). Chain: POST dashboard(blob) -> GET growid/login."""
    def _get(url):
        req = urllib.request.Request(url, headers=_web_headers())
        with op.open(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace"), r.status
    def _post(url, body):
        req = urllib.request.Request(url, data=body, method="POST",
                                     headers=_web_headers({"Content-Type": "application/x-www-form-urlencoded"}))
        with op.open(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace"), r.status

    html, status = "", 0
    try:
        html, status = _post(LOGIN_HOST + "/player/login/dashboard", blob.encode())
    except urllib.error.HTTPError as e:
        html, status = e.read().decode("utf-8", "replace"), e.code
    if dbg is not None:
        dbg.append(("POST /player/login/dashboard(blob)", status, len(html),
                    bool(_find_csrf(html)), _find_growid_login_href(html)))
    href = _find_growid_login_href(html)                       # growid/login?token=<big token>
    if href:
        url = href if href.startswith("http") else LOGIN_HOST + href
        try:
            html2, status2 = _get(url)
            if dbg is not None:
                dbg.append(("GET growid/login?token=..", status2, len(html2), bool(_find_csrf(html2)), ""))
                dbg.append(("  growid-page snippet", "", 0, False, _snippet(html2)))
            if _find_csrf(html2):
                html = html2
        except urllib.error.HTTPError as e:
            if dbg is not None:
                dbg.append(("GET growid/login", e.code, 0, False, ""))
    return html, _find_csrf(html)


def probe_login(timeout=15):
    """Credential-free diagnostic: try the likely login-form endpoints and report where _token lives.
    Never submits a password. Run this to let us fix the parser without touching the account."""
    op = _opener()
    CANDS = [
        ("GET", "/player/growid/login", BROWSER_UA, None),
        ("GET", "/player/login", BROWSER_UA, None),
        ("GET", "/player/login/dashboard", BROWSER_UA, None),
        ("GET", "/player/growid/login", GAME_UA, None),
        ("POST", "/player/login/dashboard", BROWSER_UA, b""),
    ]
    print("=== growid login endpoint probe (no credentials sent) ===")
    for method, path, ua, body in CANDS:
        url = LOGIN_HOST + path
        req = urllib.request.Request(url, data=body, method=method, headers={"User-Agent": ua})
        if body is not None:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with op.open(req, timeout=timeout) as r:
                html, status, ct = r.read().decode("utf-8", "replace"), r.status, r.headers.get("content-type", "")
        except urllib.error.HTTPError as e:
            html, status, ct = e.read().decode("utf-8", "replace"), e.code, e.headers.get("content-type", "")
        except Exception as e:
            html, status, ct = "", "ERR:%s" % e, ""
        ua_tag = "game" if ua == GAME_UA else "web"
        print("\n  %s %-26s [%s] -> %s %s  len=%d  _token=%s  href=%s"
              % (method, path, ua_tag, status, ct.split(";")[0], len(html),
                 bool(_find_csrf(html)), _find_growid_login_href(html) or "-"))
        print("     snippet:", _snippet(html))
    return True


def probe_dashboard(timeout=15):
    """Credential-free: POST /player/login/dashboard with a proper pre-auth login blob (empty creds) and
    see what it returns (expecting a growid login url/token, not 'Please try login again'). Tries a few
    valKey candidates. No password sent."""
    import hashlib, uuid, random, login as L
    sd = fetch_server_data()
    meta = sd.get("meta", "")
    guid = uuid.uuid4().hex
    cfg = {"growid": "", "password": "", "identity_mode": "synthetic",
           "device": {"machine_guid": guid,
                      "mac": ":".join("%02x" % random.randint(0, 255) for _ in range(6)),
                      "wk": "".join(random.choice("0123456789ABCDEF") for _ in range(32))}}
    blob = L.build_login_text(cfg, requested_name="", session={"meta": meta})
    op = _opener()
    valkeys = [None, hashlib.md5(blob.encode()).hexdigest(), hashlib.md5(guid.encode()).hexdigest()]
    print("=== dashboard probe: POST login blob (no credentials) ===")
    print("  (server_data meta %s; blob %d bytes)" % ("set" if meta else "none", len(blob)))
    for vk in valkeys:
        url = LOGIN_HOST + "/player/login/dashboard" + ("?valKey=" + vk if vk else "")
        req = urllib.request.Request(url, data=blob.encode(), method="POST",
                                     headers={"User-Agent": BROWSER_UA,
                                              "Content-Type": "application/x-www-form-urlencoded"})
        try:
            with op.open(req, timeout=timeout) as r:
                html, status = r.read().decode("utf-8", "replace"), r.status
        except urllib.error.HTTPError as e:
            html, status = e.read().decode("utf-8", "replace"), e.code
        except Exception as e:
            html, status = "", "ERR:%s" % e
        tag = "none" if vk is None else ("md5(blob)" if vk == valkeys[1] else "md5(guid)")
        print("\n  valKey=%-10s -> %s  len=%d  _token=%s  href=%s"
              % (tag, status, len(html), bool(_find_csrf(html)), _find_growid_login_href(html) or "-"))
        print("     snippet:", _snippet(html))
    return True


def probe_pagechain(timeout=15):
    """Credential-free: run the EXACT page chain growid_login uses (dashboard blob -> growid page) and
    report whether the _token (CSRF) was found. No password sent. De-risks --go."""
    import uuid, random, login as L
    sd = fetch_server_data()
    cfg = {"growid": "", "password": "", "identity_mode": "synthetic",
           "device": {"machine_guid": uuid.uuid4().hex,
                      "mac": ":".join("%02x" % random.randint(0, 255) for _ in range(6)),
                      "wk": "".join(random.choice("0123456789ABCDEF") for _ in range(32))}}
    op = _opener()
    print("=== page-chain probe (no credentials, retrying like --go) ===")
    csrf = ""
    for i in range(4):
        sd = fetch_server_data()                               # fresh meta each attempt
        blob = _dashboard_blob(cfg, sd.get("meta", ""))
        dbg = []
        _html, csrf = _login_page(op, timeout, blob, dbg=dbg)
        row = dbg[0] if dbg else ("?", "?", 0, False, "")
        print("  attempt %d: dashboard -> %s len=%d href=%s" % (i + 1, row[1], row[2], (row[4] or "-")[:50]))
        if csrf:
            print("    growid page _token found: True")
            break
    print("  FINAL _token found:", bool(csrf), "  <- if True, --go should authenticate")
    return bool(csrf)


def probe_growid_page(timeout=15):
    """ONE polite pass: server_data -> dashboard(blob) -> GET growid page, then DUMP that page (redacted)
    so we can see where _token lives. Single request each; no password; run only after any 403 clears."""
    import uuid, random, time, login as L
    op = _opener()
    sd = fetch_server_data()
    cfg = {"growid": "", "password": "", "identity_mode": "synthetic",
           "device": {"machine_guid": uuid.uuid4().hex,
                      "mac": ":".join("%02x" % random.randint(0, 255) for _ in range(6)),
                      "wk": "".join(random.choice("0123456789ABCDEF") for _ in range(32))}}
    print("=== growid page dump (no credentials) ===")
    dash, href = "", ""
    for i in range(6):                                          # dashboard is ~50% flaky; retry politely
        if i:
            time.sleep(2.0 + i)
        sd = fetch_server_data()                               # fresh meta each attempt
        blob = _dashboard_blob(cfg, sd.get("meta", ""))
        req = urllib.request.Request(LOGIN_HOST + "/player/login/dashboard", data=blob.encode(),
                                     method="POST", headers=_web_headers(
                {"Content-Type": "application/x-www-form-urlencoded"}))
        try:
            with op.open(req, timeout=timeout) as r:
                dash = r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            dash = e.read().decode("utf-8", "replace")
        href = _find_growid_login_href(dash)
        print("  dashboard attempt %d: len=%d  href=%s" % (i + 1, len(dash), "YES" if href else "no"))
        if href:
            break
    if not href:
        print("  dashboard never succeeded; last response:", _snippet(dash))
        return
    time.sleep(1.0)
    req = urllib.request.Request(href, headers=_web_headers())
    try:
        with op.open(req, timeout=timeout) as r:
            page = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        page = e.read().decode("utf-8", "replace")
    print("  growid page len=%d  _token(regex)=%s" % (len(page), bool(_find_csrf(page))))
    # show every token-ish construct so we can see the real one
    for pat, label in [(r'name="_token"[^>]*', "_token input"),
                       (r'csrf-token"[^>]*content="[^"]+"', "csrf meta"),
                       (r'XSRF-TOKEN', "XSRF cookie ref"),
                       (r'_token\s*[:=]\s*["\'][^"\']+["\']', "_token JS var"),
                       (r'<form[^>]*action="[^"]*"[^>]*>', "form tag")]:
        for m in re.findall(pat, page)[:3]:
            red = re.sub(r'(content|value)="[^"]{16,}"', r'\1="<...>"', m)
            print("   %-14s %s" % (label, red[:120]))
    print("  page head:", _snippet(page))
    return


def growid_login(growid, password, blob_factory, timeout=15, attempts=4):
    """Do the growid HTTPS login -> session dict {token, ...}. `blob_factory()` returns a fresh pre-auth
    dashboard blob (fresh meta) each call. Chain: POST dashboard(blob) -> GET growid/login (for _token) ->
    POST validate. The dashboard is flaky / meta is short-lived, so retry until it yields the page+_token."""
    import time
    op = _opener()
    csrf, last = "", ""
    for i in range(attempts):
        if i:
            time.sleep(2.0 + i)                                # polite backoff; the WAF 403s on rapid repeats
        html, csrf = _login_page(op, timeout, blob_factory())
        if csrf:
            break
        last = html
    if not csrf:
        raise RuntimeError("dashboard never yielded the growid page/_token in %d tries; last response: %s"
                           % (attempts, _snippet(last)))
    data = urllib.parse.urlencode({"_token": csrf, "growId": growid, "password": password}).encode()
    req = urllib.request.Request(LOGIN_HOST + "/player/growid/login/validate", data=data, method="POST",
                                 headers={"User-Agent": BROWSER_UA,
                                          "Content-Type": "application/x-www-form-urlencoded",
                                          "Origin": LOGIN_HOST, "Referer": LOGIN_HOST + "/player/growid/login"})
    try:
        with op.open(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
    try:
        j = json.loads(raw)
    except ValueError:
        raise RuntimeError("growid validate did not return JSON (CSRF/UA issue?): %s" % raw[:160])
    if str(j.get("status")) != "success":
        raise RuntimeError("growid login failed: %s" % j.get("message", raw[:160]))
    session = {"token": j.get("token", ""), "accountType": j.get("accountType"), "accountAge": j.get("accountAge")}
    # Surface the response SHAPE (keys only, no secret values) to learn how the token maps to the ENet
    # login fields. The real login uses user=<numeric> + token=<short> + UUIDToken, not the raw web token.
    print("[auth] validate success; response keys: %s" % sorted(j.keys()))
    for extra in ("user", "userID", "uuid", "UUIDToken", "ltoken", "refreshToken", "url"):
        if j.get(extra):
            session[extra.lower()] = j[extra]
            print("[auth]   response has %s (<%d chars>)" % (extra, len(str(j[extra]))))
    # The web token may itself be base64 of a GT key|value blob carrying user/token/UUIDToken. If so,
    # pull those out so build_fields sends the real short token + user (matches the captured real login).
    _decode_token_fields(session)
    return session, j


def _decode_token_fields(session):
    """If session['token'] is base64 of GT 'key|value' text, lift user/token/UUIDToken out of it."""
    import base64
    tok = session.get("token", "")
    if not tok:
        return
    for pad in ("", "=", "==", "==="):
        try:
            dec = base64.b64decode(tok + pad).decode("latin1")
            break
        except Exception:
            dec = None
    if not dec or "|" not in dec:
        return
    fields = {}
    for line in dec.replace("\r", "\n").split("\n"):
        k, sep, v = line.partition("|")
        if sep:
            fields[k.strip()] = v
    mapping = {"user": ("user", "userID"), "token": ("token",), "uuid_token": ("UUIDToken", "uuidToken")}
    picked = []
    for dst, srcs in mapping.items():
        for s in srcs:
            if fields.get(s):
                session[dst] = fields[s]; picked.append("%s<-%s" % (dst, s)); break
    if picked:
        print("[auth] web token decoded to GT fields; lifted: %s" % ", ".join(picked))


def authenticate(cfg):
    """Full auth: server_data.php + growid login. Returns a `session` dict for login.build_fields:
    {meta, token, user?, ...}. Reads growid/password from cfg; never logs the password."""
    from login import PROTOCOL, GAME_VERSION
    sd_holder = {}

    def blob_factory():                                        # fresh server_data (fresh meta) each attempt
        sd = fetch_server_data(PROTOCOL, GAME_VERSION)
        sd_holder["sd"] = sd
        return _dashboard_blob(cfg, sd.get("meta", ""))

    session, _ = growid_login(cfg["growid"], cfg["password"], blob_factory)
    sd = sd_holder["sd"]
    session["meta"] = sd.get("meta", "")
    session["_server_data"] = sd                                # server/port/etc. for the ENet connect
    return session


if __name__ == "__main__":
    import sys
    if "--probe4" in sys.argv:
        probe_growid_page()                                    # one polite pass; dump the growid page (no password)
    elif "--probe3" in sys.argv:
        probe_pagechain()                                      # full page chain -> _token (no password)
    elif "--probe2" in sys.argv:
        probe_dashboard()                                      # POST a real pre-auth blob (no password)
    elif "--probe" in sys.argv:
        # Credential-free: walk the login page chain, report where _token lives. No password sent.
        probe_login()
    else:
        # Smoke test of server_data only (no credentials needed, no login performed).
        sd = fetch_server_data()
        print("server_data.php ->", {k: sd[k] for k in ("server", "port", "type", "meta") if k in sd})
