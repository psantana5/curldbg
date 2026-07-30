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

skip_result() {
    local desc="$1" reason="$2"
    SKIPPED=$((SKIPPED + 1))
    echo "  SKIP: $desc ($reason)" >&2
}

fail_result() {
    local desc="$1" reason="$2"
    FAILED=$((FAILED + 1))
    echo "  FAIL: $desc ($reason)" >&2
}

fetch_code() {
    local url="$1" out="${2:-/dev/null}"
    "$CURLDBG" -s -o "$out" -w "%{http_code}" "$url" 2>/dev/null || true
}

fetch_http_version() {
    local url="$1"
    "$CURLDBG" -s -o /dev/null -w "%{http_version}" "$url" 2>/dev/null || true
}

assert_http2_or_skip() {
    TOTAL=$((TOTAL + 1))
    local desc="$1" url="$2"
    local ver
    ver=$(fetch_http_version "$url")
    case "$ver" in
        HTTP/2) PASSED=$((PASSED + 1)) ;;
        "")     skip_result "$desc" "unreachable" ;;
        500|501|502|503|504) skip_result "$desc" "remote server returned HTTP $ver" ;;
        *)      fail_result "$desc" "HTTP version: $ver" ;;
    esac
}

assert_http200_or_skip() {
    TOTAL=$((TOTAL + 1))
    local desc="$1" url="$2"
    local code
    code=$(fetch_code "$url")
    case "$code" in
        200)    PASSED=$((PASSED + 1)) ;;
        0|"")   skip_result "$desc" "unreachable" ;;
        5??)    skip_result "$desc" "remote server returned HTTP $code" ;;
        *)      fail_result "$desc" "HTTP $code" ;;
    esac
}

assert_json200_or_skip() {
    TOTAL=$((TOTAL + 1))
    local desc="$1" url="$2"
    local tmp
    tmp=$(mktemp)
    trap 'rm -f "$tmp"' RETURN
    local code
    code=$(fetch_code "$url" "$tmp")
    case "$code" in
        200)
            if python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$tmp" >/dev/null 2>&1; then
                PASSED=$((PASSED + 1))
            else
                fail_result "$desc" "invalid JSON"
            fi
            ;;
        0|"")   skip_result "$desc" "unreachable" ;;
        5??)    skip_result "$desc" "remote server returned HTTP $code" ;;
        *)      fail_result "$desc" "HTTP $code" ;;
    esac
    rm -f "$tmp"
    trap - RETURN
}

echo "  test_http2_public: testing against public HTTP/2 servers"

assert_http2_or_skip "nghttp2.org returns HTTP/2" "https://nghttp2.org/"
assert_http200_or_skip "nghttp2.org returns 200" "https://nghttp2.org/"

assert_http2_or_skip "httpbin.org/get returns HTTP/2" "https://httpbin.org/get"
assert_http200_or_skip "httpbin.org/get returns 200" "https://httpbin.org/get"
assert_json200_or_skip "httpbin.org/headers returns JSON" "https://httpbin.org/headers"
assert_http2_or_skip "httpbin.org redirect via HTTP/2" "https://httpbin.org/redirect/1"

echo "  test_http2_public: $PASSED passed, $SKIPPED skipped, $FAILED failed out of $TOTAL tests"

if [ $FAILED -gt 0 ]; then
    exit 1
fi

exit 0
