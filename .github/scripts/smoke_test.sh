#!/usr/bin/env bash
# Smoke test for the built ajons-uploader binary.
# Runs the BUILT binary (not python source) from a clean temp directory outside
# the repo, with PYTHONPATH unset: --version, status --json, then serve ->
# confirm it stays running for 10s -> stop. Fails on any step failure.
set -euo pipefail

BINARY_NAME="${1:?usage: smoke_test.sh <binary_name> <repo_root> <platform> <expected_version>}"
REPO_ROOT="${2:?usage: smoke_test.sh <binary_name> <repo_root> <platform> <expected_version>}"
PLATFORM="${3:-linux}"
EXPECTED_VERSION="${4:-1.1.5}"

STORE_SERVICE="com.ajonswebtools.ajons-uploader"

BIN_PATH="$REPO_ROOT/dist/$BINARY_NAME"
if [ ! -f "$BIN_PATH" ]; then
  echo "ERROR: built binary not found at $BIN_PATH" >&2
  exit 1
fi

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

cp "$BIN_PATH" "$TMPDIR/"
cd "$TMPDIR"

# PYTHONPATH must be unset so the frozen binary is tested, not source.
unset PYTHONPATH

EXE="./$BINARY_NAME"

# Clear any stale daemon from a previous run.
"$EXE" stop >/dev/null 2>&1 || true

echo "=== --version ==="
VERSION_OUT=$("$EXE" --version)
echo "$VERSION_OUT"
echo "$VERSION_OUT" | grep -q "^ajons-uploader ${EXPECTED_VERSION}$" || {
  echo "ERROR: --version output '$VERSION_OUT' does not match expected 'ajons-uploader ${EXPECTED_VERSION}'" >&2
  exit 1
}
echo "--version matches expected ${EXPECTED_VERSION}"

echo "=== status --json ==="
STATUS_JSON=$("$EXE" status --json)
echo "$STATUS_JSON"
python3 - "$STATUS_JSON" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
for key in ("token_valid", "needs_repair", "daemon_running"):
    if key not in d:
        print(f"ERROR: status --json missing key: {key}", file=sys.stderr)
        sys.exit(1)
print("status --json contains token_valid, needs_repair, daemon_running")
PY

echo "=== serve (stays running 10s) ==="
if [ "$PLATFORM" = "linux" ]; then
  "$EXE" serve --concurrency 1 --allow-insecure-file > serve.log 2>&1 &
else
  echo "=== keyring read/write (same code path as daemon) ==="
  python3 - "$STORE_SERVICE" <<'PY'
import keyring, sys
service = sys.argv[1]
keyring.set_password(service, "smoke-test", "dummy-secret")
val = keyring.get_password(service, "smoke-test")
assert val == "dummy-secret", repr(val)
keyring.delete_password(service, "smoke-test")
print("keyring read/write OK")
PY
  "$EXE" serve --concurrency 1 > serve.log 2>&1 &
fi
SERVE_PID=$!
sleep 10
if ! kill -0 "$SERVE_PID" 2>/dev/null; then
  echo "ERROR: serve did not stay running; serve.log:" >&2
  cat serve.log >&2
  exit 1
fi
echo "serve is running (PID $SERVE_PID) after 10s"

echo "=== status --json while daemon running ==="
"$EXE" status --json

echo "=== stop ==="
"$EXE" stop
sleep 2
if kill -0 "$SERVE_PID" 2>/dev/null; then
  echo "ERROR: serve still running after stop" >&2
  kill "$SERVE_PID" 2>/dev/null || true
  exit 1
fi
echo "serve stopped"

echo "SMOKE TEST PASSED for $BINARY_NAME ($PLATFORM)"
