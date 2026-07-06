#!/bin/bash
set -e
PORT=$1
BASE="http://127.0.0.1:$PORT"
DIR="$(cd "$(dirname "$0")" && pwd)"
FAILED=0

run_test() {
    local name=$1
    echo "  $name..."
    if bash "$DIR/$name" "$PORT"; then
        echo "    OK"
    else
        echo "    FAILED"
        FAILED=1
    fi
}

# Verify server is alive
if ! ./curldbg -s -o /dev/null -w "%{http_code}" "$BASE/" 2>/dev/null | grep -q 200; then
    echo "ERROR: testd not responding on port $PORT"
    exit 1
fi

run_test test_basic.sh
run_test test_redirect.sh
run_test test_chunked.sh
run_test test_malformed.sh

if [ $FAILED -eq 0 ]; then
    echo "all integration tests passed"
else
    echo "some tests failed"
    exit 1
fi