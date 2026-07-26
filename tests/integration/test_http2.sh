#!/bin/bash
set +e

# HTTP/2 integration test.  This test is self-contained: it creates a local venv
# with the h2 package, generates a self-signed TLS certificate, starts the Python
# HTTP/2 test server, and runs curldbg against it.

PASS=0; FAIL=0

assert_eq() {
    local label=$1 expected=$2 actual=$3
    if [ "$actual" = "$expected" ]; then ((PASS++))
    else echo "  FAIL [$label]: expected '$expected', got '$actual'"; ((FAIL++)); fi
}

assert_status() {
    local label=$1 expected=$2 url=$3
    shift 3
    local actual
    actual=$($CDBG -k "$@" "$url" -o /dev/null -w "%{http_code}" 2>/dev/null)
    assert_eq "$label" "$expected" "$actual"
}

CDBG="${CURLDBG_BIN:-./curldbg} -s"

# Locate the project root so we can find the test server.
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"

# Optional port argument (ignored; we manage our own server).
shift 2>/dev/null || true

# Build a venv inside the build directory so we do not pollute the system.
VENV_DIR="$ROOT/obj/h2_venv"
if [ ! -x "$VENV_DIR/bin/python3" ]; then
    echo "  setting up h2 venv..."
    if ! python3 -m venv "$VENV_DIR" >/dev/null 2>&1; then
        echo "  SKIP: cannot create Python venv for HTTP/2 test server"
        exit 0
    fi
    if ! "$VENV_DIR/bin/pip" install -q h2 2>/dev/null; then
        echo "  SKIP: cannot install h2 package"
        exit 0
    fi
fi

if [ ! -x "$VENV_DIR/bin/python3" ]; then
    echo "  SKIP: no venv available"
    exit 0
fi

CERT_DIR=$(mktemp -d)
CERT="$CERT_DIR/cert.pem"
KEY="$CERT_DIR/key.pem"

cleanup() {
    if [ -n "$H2PID" ]; then kill "$H2PID" 2>/dev/null; wait "$H2PID" 2>/dev/null; fi
    rm -rf "$CERT_DIR"
}
trap cleanup EXIT

if ! openssl req -x509 -newkey rsa:2048 -keyout "$KEY" -out "$CERT" -days 1 -nodes \
        -subj '/CN=localhost' 2>/dev/null; then
    echo "  SKIP: cannot generate self-signed certificate"
    exit 0
fi

PORT_FILE=$(mktemp)
"$VENV_DIR/bin/python3" "$ROOT/tests/server/h2d.py" "$CERT" "$KEY" > "$PORT_FILE" 2>&1 &
H2PID=$!

for _ in $(seq 1 50); do
    if [ -s "$PORT_FILE" ]; then break; fi
    sleep 0.1
done

if ! [ -s "$PORT_FILE" ]; then
    echo "  FAIL: HTTP/2 test server did not start"
    cat "$PORT_FILE" 2>/dev/null || true
    exit 1
fi

PORT=$(cat "$PORT_FILE")
rm -f "$PORT_FILE"
BASE="https://127.0.0.1:$PORT"

# Wait for the server to accept TLS connections.
for _ in $(seq 1 30); do
    if "$CDBG" -k "$BASE/" -o /dev/null -w "%{http_code}" 2>/dev/null | grep -q 200; then
        break
    fi
    sleep 0.1
done

# --- GET / returns plain text body ---
BODY=$($CDBG -k "$BASE/" -o - 2>/dev/null)
assert_eq "GET / body" "Hello HTTP/2" "$BODY"

# --- HEAD / returns 200 with no body ---
assert_status "HEAD / status" "200" "$BASE/" -I
HEAD_LEN=$($CDBG -k -I "$BASE/" -o - 2>/dev/null | wc -c)
assert_eq "HEAD / no body" "0" "$HEAD_LEN"

# --- POST /echo echoes the request body ---
BODY=$($CDBG -k -d 'hello=world' "$BASE/echo" -o - 2>/dev/null)
assert_eq "POST /echo body" "hello=world" "$BODY"

# --- POST /status with --data works ---
BODY=$($CDBG -k -d 'foo=bar' "$BASE/status" -o - 2>/dev/null)
assert_eq "POST /status body" "status: ok" "$BODY"

# --- JSON endpoint ---
BODY=$($CDBG -k "$BASE/json" -o - 2>/dev/null)
assert_eq "GET /json body" '{"ok": true, "proto": "h2"}' "$BODY"

# --- Cookie endpoint ---
BODY=$($CDBG -k "$BASE/cookie" -o - 2>/dev/null)
assert_eq "GET /cookie body" "cookie set" "$BODY"

# --- /missing returns 404 ---
assert_status "GET /missing status" "404" "$BASE/missing"

echo "http2: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
