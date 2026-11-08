"""Bounded Railway live test; config comes only from SENTRY_CONFIG_JSON."""
import json
import os
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "core"))
from sentry import Sentry


class TestLimit(BaseException):
    pass


def read_config(raw):
    try:
        cfg = json.loads(raw)
    except (ValueError, TypeError):
        raise ValueError("SENTRY_CONFIG_JSON must contain valid JSON") from None
    if not isinstance(cfg, dict):
        raise ValueError("SENTRY_CONFIG_JSON must contain a JSON object")
    if any(not isinstance(cfg.get(k), str) or not cfg[k].strip() for k in ("growid", "password", "world")):
        raise ValueError("Configuration must supply growid, password, and world")
    if cfg.get("identity_mode") != "captured":
        raise ValueError("Use the existing working captured burner identity for this test")
    identity = cfg.get("identity")
    if not isinstance(identity, dict) or any(identity.get(k) in (None, "") for k in ("rid", "mac", "klv", "hash", "hash2")):
        raise ValueError("The existing captured identity is incomplete")
    if cfg.get("proxy") is not None:
        raise ValueError("This is a direct Railway test; remove proxy or set it to null")
    cfg["verbose"] = False
    cfg["netguard"] = True
    return cfg


class ObservedSentry(Sentry):
    world_entered_at = None

    def _on_variant(self, values):
        super()._on_variant(values)
        if self.in_world and self.world_entered_at is None:
            self.world_entered_at = time.monotonic()


def run_session(cfg):
    import netguard
    import proxy_transport
    proxy_transport.configure(None)
    netguard.install()
    cfg["_auth_diagnostics"] = []
    bot = ObservedSentry(cfg)
    started = time.monotonic()
    report = {"test": "railway_live", "revision": "auth-fix-v4", "mode": "direct", "limit_seconds": 300,
              "joined_world": False, "in_world_seconds": 0, "limit_reached": False}
    print("[live-test] one session, at most 300 seconds; existing burner identity; direct Railway route", flush=True)
    try:
        outcome, _detail = bot._run_once()  # deliberately no endless supervisor/reconnect loop
        report["outcome"] = outcome
    except TestLimit:
        report.update(outcome="test_limit", limit_reached=True)
    except KeyboardInterrupt:
        report["outcome"] = "interrupted"
    except Exception as exc:
        # Do not print exception values/tracebacks that could contain login URLs.
        report.update(outcome="error", error_type=type(exc).__name__)
    finally:
        ended = time.monotonic()
        report["elapsed_seconds"] = round(ended - started, 1)
        if bot.world_entered_at is not None:
            report["joined_world"] = True
            report["in_world_seconds"] = round(ended - bot.world_entered_at, 1)
        bot._cleanup()
        report["auth_diagnostics"] = cfg["_auth_diagnostics"]
        for event in report["auth_diagnostics"]:
            print("[auth-diag] " + json.dumps(event), flush=True)
    return report


def main():
    raw = os.environ.pop("SENTRY_CONFIG_JSON", None)
    if raw is None:
        print("[live-test] SENTRY_CONFIG_JSON is missing. No connection attempted.")
        return
    try:
        cfg = read_config(raw)
    except ValueError as exc:
        print("[live-test]", str(exc), "No connection attempted.")
        return
    del raw
    if not hasattr(signal, "setitimer"):
        print("[live-test] This bounded runner requires Linux. No connection attempted.")
        return

    def expired(_sig, _frame):
        raise TestLimit()

    def stopped(_sig, _frame):
        raise KeyboardInterrupt()

    signal.signal(signal.SIGALRM, expired)
    signal.signal(signal.SIGTERM, stopped)
    signal.setitimer(signal.ITIMER_REAL, 300)
    try:
        result = run_session(cfg)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    print("[live-test] SUMMARY " + json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
