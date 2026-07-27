#!/bin/bash
# HTTP/2 integration test
# This test starts its own Python HTTP/2 server with TLS.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
TMPDIR="${TMPDIR:-/tmp}"
CERT="$TMPDIR/h2test.crt"
KEY="$TMPDIR/h2test.key"

if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    openssl req -x509 -newkey rsa:2048 -keyout "$KEY" -out "$CERT" \
        -days 7 -nodes -subj '/CN=localhost' 2>/dev/null
fi

PYTHON=""
for p in python3 python; do
    if command -v "$p" >/dev/null 2>&1; then
        PYTHON="$p"
        break
    fi
done
if [ -z "$PYTHON" ]; then
    echo "skipped (no Python)" >&2
    exit 0
fi

H2_SERVER="$DIR/../server/h2d.py"
if [ ! -f "$H2_SERVER" ]; then
    echo "FAIL: h2d.py not found" >&2
    exit 1
fi

H2_VENV="$TMPDIR/h2test_venv"
if [ ! -d "$H2_VENV" ]; then
    "$PYTHON" -m venv "$H2_VENV" 2>/dev/null || true
fi
if [ -f "$H2_VENV/bin/python" ]; then
    PYTHON="$H2_VENV/bin/python"
fi
"$PYTHON" -c "import h2" 2>/dev/null || "$PYTHON" -m pip install h2 2>/dev/null || {
    echo "skipped (h2 library not available)" >&2
    exit 0
}

# Use CURLDBG_BIN if set, else first arg
CURLDBG="${CURLDBG_BIN:-$1}"
if [ -z "$CURLDBG" ]; then
    echo "FAIL: no curldbg binary specified" >&2
    exit 1
fi

TOTAL=0
PASSED=0
FAILED=0

assert() {
    TOTAL=$((TOTAL + 1))
    local desc="$1"
    shift
    if eval "$@"; then
        PASSED=$((PASSED + 1))
    else
        FAILED=$((FAILED + 1))
        echo "  FAIL: $desc" >&2
    fi
}

# Start h2d server
PORT_FILE="$TMPDIR/h2test_port.txt"
rm -f "$PORT_FILE"
"$PYTHON" "$H2_SERVER" 0 --cert "$CERT" --key "$KEY" > "$PORT_FILE" 2>/dev/null &
H2PID=$!
sleep 1
PORT=$(head -1 "$PORT_FILE" 2>/dev/null || echo "")
if [ -z "$PORT" ]; then
    echo "FAIL: could not start h2d server" >&2
    kill $H2PID 2>/dev/null; wait $H2PID 2>/dev/null
    exit 1
fi

# Kill server on exit
cleanup() { kill $H2PID 2>/dev/null || true; wait $H2PID 2>/dev/null || true; rm -f "$PORT_FILE"; }
trap cleanup EXIT

echo "  test_http2: h2d on port $PORT"

BASE="https://localhost:$PORT"

assert "HTTP/2 GET returns 200" \
    '$CURLDBG -s --insecure -o /dev/null -w "%{http_code}" "$BASE/" 2>/dev/null | grep -q "^200$"'

assert "HTTP/2 GET returns body" \
    '$CURLDBG -s --insecure "$BASE/" 2>/dev/null | grep -q "Hello from HTTP/2 test server"'

assert "HTTP/2 404 status" \
    '$CURLDBG -s --insecure -o /dev/null -w "%{http_code}" "$BASE/status404" 2>/dev/null | grep -q "^404$"'

assert "HTTP/2 500 status" \
    '$CURLDBG -s --insecure -o /dev/null -w "%{http_code}" "$BASE/status500" 2>/dev/null | grep -q "^500$"'

assert "HTTP/2 with verbose output" \
    '$CURLDBG -v --insecure -o /dev/null "$BASE/" 2>&1 | grep -q "HTTP/2"'

echo "  test_http2: $PASSED/$TOTAL passed"
if [ $FAILED -gt 0 ]; then
    exit 1
fi
