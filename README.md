# Railway live test — maximum five minutes

The direct Railway check passed server discovery and ENet. This package tests
web authentication, redirect login, world join, and a short observation period.
It is not the final 24/7 deployment and does not use the endless reconnect loop.

1. Replace the files in the connectivity-test repository with this extracted
   package. Keep Dockerfile at the root and use its default start command.
2. In the Railway service's Variables tab, create ONE variable named
   `SENTRY_CONFIG_JSON`. Its value is the complete JSON text from your existing
   working gt_sentry/config.json. Preserve the captured burner identity. `proxy`
   must be absent or null. Do not commit config.json or paste it into chat/logs.
3. Seal this variable in its menu if available. Sealing prevents retrieval through
   the dashboard/API, not access by Railway or by your running application.
4. Keep restart policy Never, no HTTP health check and no public domain. Stop any
   other copy logged in as this same burner account before deployment.
5. Deploy the staged code/variable changes. It attempts one session and stops on
   failure or after at most 300 seconds total. It uses normal auth/connection
   retries within that session, but no repeated full-session reconnect loop.
6. Share the log from `[live-test]` onward, especially the final SUMMARY. Treat
   chat/player names and account/world identifiers in normal sentry logs as
   private as appropriate; redact those before sharing. Never share the variable.

Expected milestones: web validation success, ENet connection, stage-1 login,
redirect(s), stage-2 login, and `IN WORLD`. The JSON summary reports actual time
in the world; five minutes total does not mean five minutes in-world. A clean
test timeout is expected. Failed checks also exit cleanly to avoid platform
restart loops. Missing/invalid config causes no network attempt.

No credentials are included in this archive, written to a config file, or
printed by this wrapper. Existing identity values are not regenerated. Runtime
configuration is read from Railway's environment into process memory. The
wrapper removes the variable from its environment after reading it; this does
not remove Railway's stored copy or make it inaccessible to the hosting provider.

No administrator privileges, proxy, VPN, inbound port or persistent volume is
needed. Credentials and the session remain within Railway's trust boundary;
game session tokens still travel over the game's unencrypted ENet transport.

## Relevant provider notice

Railway published an October 21, 2026 disclosure concerning possible access to
customer environment variables, including some decrypted values. Our preceding
connectivity tests contained no credentials. Use a unique burner-account password
for this test. This notice does not establish that newly added variables are
compromised, nor does sealing a variable remove provider-side trust.

- https://docs.railway.com/variables
- https://blog.railway.com/p/security-disclosure-wednesday-october-21st
