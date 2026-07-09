#!/bin/bash
set -e
TESTD="$1"
CURLDBG="$2"
DIR="$(cd "$(dirname "$0")" && pwd)"
FAILED=0

export CURLDBG_BIN="$CURLDBG"

setarch_prefix=""
if command -v setarch >/dev/null 2>&1; then
    setarch_prefix="setarch $(uname -m) -R"
fi

run_test() {
    local name=$1 port=$2
    echo "  $name..."
    if bash "$DIR/$name" "$port"; then
        echo "    OK"
    else
        echo "    FAILED"
        FAILED=1
    fi
}

$setarch_prefix "$TESTD" >/tmp/testd.log 2>&1 &
TDPID=$!
until [ -s /tmp/testd.log ]; do sleep 0.1; done
PORT=$(head -1 /tmp/testd.log)
echo "=== integration tests (port $PORT) ==="

if ! "$CURLDBG" -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT/" 2>/dev/null | grep -q 200; then
    echo "ERROR: testd not responding on port $PORT"
    kill $TDPID 2>/dev/null; wait $TDPID 2>/dev/null
    rm -f /tmp/testd.log
    exit 1
fi

run_test test_basic.sh "$PORT"
run_test test_redirect.sh "$PORT"
run_test test_chunked.sh "$PORT"
run_test test_malformed.sh "$PORT"

kill $TDPID 2>/dev/null
wait $TDPID 2>/dev/null
rm -f /tmp/testd.log

if [ $FAILED -eq 0 ]; then
    echo "all integration tests passed"
else
    echo "some tests failed"
    exit 1
fi
