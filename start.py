"""Provide environment configuration to the archived client's normal CLI."""
import json
import os
import sys
import tempfile


def main():
    raw = os.environ.pop("SENTRY_CONFIG_JSON", None)
    try:
        cfg = json.loads(raw)
        if not isinstance(cfg, dict):
            raise ValueError()
        if any(not isinstance(cfg.get(k), str) or not cfg[k].strip()
               for k in ("growid", "password", "world")):
            raise ValueError()
        if cfg.get("proxy") is not None:
            print("[baseline] Direct test requires proxy absent or null. No connection attempted.", flush=True)
            return
    except (ValueError, TypeError):
        print("[baseline] Missing or invalid SENTRY_CONFIG_JSON. No connection attempted.", flush=True)
        return
    # mkstemp creates a private mode-0600 file on Linux. Preserve the supplied
    # configuration exactly; the archived CLI reads it using its normal path.
    fd, path = tempfile.mkstemp(prefix="sentry-config-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(raw)
    print("[baseline] archived client; normal sentry.py --go; direct route; no five-minute limit", flush=True)
    os.execv(sys.executable, [sys.executable, "/app/sentry.py", "--config", path, "--go"])


if __name__ == "__main__":
    main()
