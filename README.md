# Archived baseline for Railway

Replace the deployment repository contents with this package. Dockerfile must
be at the repository root. Remove any Railway custom start command so Docker's
default runs. Keep the existing sealed SENTRY_CONFIG_JSON variable, containing
the working captured burner configuration with proxy absent or null. Do not
commit config.json. Stop other instances using this burner before deployment.
Use restart policy Never and no HTTP health check. Deploy once.

This runs the normal sentry.py --go entry point, including its own reconnect
loop. There is no five-minute limit. Stop the Railway service after observing
success or the first failed login/retry; do not leave a failing test retrying.
Share the relevant logs, redacting account/world details, tokens and any
server-response snippets. This is the archived client's original logging.

The eight runtime files are byte-for-byte copies from the first
railway-live-test-kit.zip, before the v2-v5 authentication changes. Their hashes
are in BASELINE-SHA256.json. There is no verified pre-proxy working snapshot in
the current workspace, so this is an archived baseline, not a claim that the
files exactly match the earlier successful residential run.

Only Dockerfile and start.py provide hosting integration. start.py writes the
unchanged environment configuration to a private temporary file in the running
container, then replaces itself with the normal client process. The file remains
for the container lifetime. No credentials are included in this package/image.
The live-test wrapper and subsequent authentication changes are not included.
