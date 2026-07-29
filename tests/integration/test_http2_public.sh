#!/bin/bash
# HTTP/2 public endpoint integration test
# Tests curldbg against known HTTP/2-capable public servers.

set -e

CURLDBG="${CURLDBG_BIN:-$1}"
if [ -z "$CURLDBG" ]; then
    echo "FAIL: no curldbg binary specified" >&2
    exit 1
fi

TOTAL=0
PASSED=0
FAILED=0
SKIPPED=0

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

assert_http200_or_skip() {
    TOTAL=$((TOTAL + 1))

    local desc="$1"
    local url="$2"

    code=$("$CURLDBG" -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)

    case "$code" in
        200)
            PASSED=$((PASSED + 1))
            ;;
        500|501|502|503|504)
            SKIPPED=$((SKIPPED + 1))
            echo "  SKIP: $desc (remote server returned HTTP $code)"
            ;;
        *)
            FAILED=$((FAILED + 1))
            echo "  FAIL: $desc (HTTP $code)"
            ;;
    esac
}

echo "  test_http2_public: testing against public HTTP/2 servers"

# nghttp2.org
assert "nghttp2.org returns HTTP/2" \
    '$CURLDBG -s -o /dev/null -w "%{http_version}" "https://nghttp2.org/" 2>/dev/null | grep -q "^HTTP/2$"'

assert_http200_or_skip \
    "nghttp2.org returns 200" \
    "https://nghttp2.org/"

# httpbin.org
assert "httpbin.org/get returns HTTP/2" \
    '$CURLDBG -s -o /dev/null -w "%{http_version}" "https://httpbin.org/get" 2>/dev/null | grep -q "^HTTP/2$"'

assert_http200_or_skip \
    "httpbin.org/get returns 200" \
    "https://httpbin.org/get"

assert "httpbin.org/headers returns JSON" \
    '$CURLDBG -s "https://httpbin.org/headers" 2>/dev/null | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null'

assert "httpbin.org redirect via HTTP/2" \
    '$CURLDBG -s -L -o /dev/null -w "%{http_version}" "https://httpbin.org/redirect/1" 2>/dev/null | grep -q "^HTTP/2$"'

echo "  test_http2_public: $PASSED passed, $SKIPPED skipped, $FAILED failed out of $TOTAL tests"

if [ $FAILED -gt 0 ]; then
    exit 1
fi

exit 0
