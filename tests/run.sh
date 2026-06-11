#!/bin/sh
# curldbg test suite
# Run: cd tests && sh run.sh
# Requires: test server reachable (httpbin.org or local)

CURLDBG="${CURLDBG:-../curldbg}"
PASS=0
FAIL=0
TEST_URL="${TEST_URL:-https://httpbin.org/get}"
HTTP_URL="${HTTP_URL:-http://httpbin.org/get}"

pass() { PASS=$((PASS+1)); echo "  PASS: $*"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL: $*"; }

assert_exit() {
    local expected="$1" desc="$2"; shift 2
    $CURLDBG -sS -o /dev/null "$@" 2>/dev/null
    local got=$?
    if [ "$got" = "$expected" ]; then
        pass "$desc"
    else
        fail "$desc (exit $got, expected $expected)"
    fi
}

assert_exit_raw() {
    local expected="$1" desc="$2"; shift 2
    $CURLDBG "$@" 2>/dev/null
    local got=$?
    if [ "$got" = "$expected" ]; then
        pass "$desc"
    else
        fail "$desc (exit $got, expected $expected)"
    fi
}

assert_out_contains() {
    local pattern="$1" desc="$2"; shift 2
    local out
    out=$($CURLDBG -sS "$@" 2>/dev/null)
    local got=$?
    case "$out" in
        *"$pattern"*)
            pass "$desc"
            ;;
        *)
            echo "$out" | grep -qF "$pattern" && pass "$desc" || fail "$desc (expected stdout to contain '$pattern')"
            ;;
    esac
    return $got
}

assert_stderr_contains() {
    local pattern="$1" desc="$2"; shift 2
    local out
    out=$($CURLDBG -sS "$@" 2>&1 >/dev/null)
    case "$out" in
        *"$pattern"*)
            pass "$desc"
            ;;
        *)
            fail "$desc (expected stderr to contain '$pattern', got: $out)"
            ;;
    esac
}

assert_not_exit() {
    local unexpected="$1" desc="$2"; shift 2
    $CURLDBG -sS -o /dev/null "$@" 2>/dev/null
    local got=$?
    if [ "$got" != "$unexpected" ]; then
        pass "$desc"
    else
        fail "$desc (unexpected exit $got)"
    fi
}

echo "=== curldbg test suite ==="
echo

# --- Basic ---
echo "--- Basic ---"
assert_exit 0 "GET $TEST_URL" "$TEST_URL"

# --- HTTPS ---
echo "--- HTTPS ---"
assert_exit 0 "HTTPS request" "$TEST_URL"

# --- -d/--data ---
echo "--- -d/--data ---"
assert_exit 0 "-d string data" -d "foo=bar" "$TEST_URL"
assert_exit 0 "-d with multiple -d" -d "a=1" -d "b=2" "$TEST_URL"
assert_exit 0 "--data-binary" --data-binary "test" "$TEST_URL"

# --- -d @file ---
echo "--- -d @file ---"
echo -n "filedata" > /tmp/curldbg_test_data.txt
assert_exit 0 "-d @file" -d "@/tmp/curldbg_test_data.txt" "$TEST_URL"
rm -f /tmp/curldbg_test_data.txt

# --- -sS silent/show-error ---
echo "--- -sS ---"
assert_exit 0 "-s (silent)" -s "$TEST_URL"
 assert_exit 0 "-S (show-error)" -S "$TEST_URL"

# --- -f/--fail ---
echo "--- -f/--fail ---"
# -f flag accepted (no error on parse), exit code depends on server response
$CURLDBG -sS -f -o /dev/null "$TEST_URL" 2>/dev/null
echo "  INFO: -f on test URL exited $?"

# --- -L/--location and --location ---
echo "--- -L/--location ---"
timeout 10 $CURLDBG -sS -L -o /dev/null "https://httpbin.org/redirect/1" 2>/dev/null
if [ $? -eq 0 ]; then
    pass "-L follow redirect"
else
    fail "-L follow redirect"
fi
timeout 10 $CURLDBG -sS --location -o /dev/null "https://httpbin.org/redirect/1" 2>/dev/null
if [ $? -eq 0 ]; then
    pass "--location long form"
else
    fail "--location long form"
fi

# --- -I/--head ---
echo "--- -I/--head ---"
assert_exit 0 "-I HEAD request" -I "$TEST_URL"
assert_exit 0 "--head long form" --head "$TEST_URL"

# --- -v/--verbose ---
echo "--- -v/--verbose ---"
assert_stderr_contains "> GET" "-v shows request line" -v "$TEST_URL"
assert_stderr_contains "< HTTP" "-v shows response line" -v "$TEST_URL"

# --- -A/--user-agent ---
echo "--- -A/--user-agent ---"
assert_stderr_contains "TestUA/1.0" "-A custom UA" -A "TestUA/1.0" -v "$TEST_URL"
assert_stderr_contains "TestUA2" "--user-agent long form" --user-agent "TestUA2" -v "$TEST_URL"

# --- -H custom header ---
echo "--- -H ---"
assert_stderr_contains "X-Custom: val" "-H custom header" -H "X-Custom: val" -v "$TEST_URL"

# --- -H Host override ---
echo "--- -H Host override ---"
assert_stderr_contains "Host: example.com" "-H Host override" -H "Host: example.com" -v "$TEST_URL"
# Should NOT contain auto-generated Host (after user's)
timeout 10 sh -c '$1 -sS -H "Host: myhost.test" -v -o /dev/null $2 2>&1 >/dev/null | grep -v "> Host: myhost.test" | grep -q "> Host:"' _ "$CURLDBG" "$TEST_URL"
if [ $? -eq 0 ]; then
    fail "-H Host override should suppress auto Host header"
else
    pass "-H Host override suppresses auto Host header"
fi

# --- --progress-bar (no-op) ---
echo "--- --progress-bar ---"
assert_exit 0 "--progress-bar accepted" --progress-bar "$TEST_URL"

# --- --max-time ---
echo "--- --max-time ---"
assert_exit 0 "--max-time allows fast request" --max-time 5000 "$TEST_URL"
# with --max-time 1 (1ms), even fast requests should exceed the deadline
assert_not_exit 0 "--max-time 1ms times out" --max-time 1 "$TEST_URL"

# --- -k/--insecure ---
echo "--- -k/--insecure ---"
assert_exit 0 "-k insecure TLS" -k "https://httpbin.org/get"

# --- -4/-6 ---
echo "--- -4/-6 ---"
assert_exit 0 "-4 IPv4" -4 "$TEST_URL"

# --- --no-happy-eyeballs ---
echo "--- --no-happy-eyeballs ---"
assert_exit 0 "--no-happy-eyeballs" --no-happy-eyeballs "$TEST_URL"

# --- --connect-timeout ---
echo "--- --connect-timeout ---"
assert_exit 0 "--connect-timeout" --connect-timeout 5000 "$TEST_URL"

# --- --read-timeout ---
echo "--- --read-timeout ---"
assert_exit 0 "--read-timeout" --read-timeout 5000 "$TEST_URL"

# --- --max-redirs ---
echo "--- --max-redirs ---"
timeout 10 $CURLDBG -sS --max-redirs 5 -L -o /dev/null "https://httpbin.org/redirect/1" 2>/dev/null
if [ $? -eq 0 ]; then
    pass "--max-redirs"
else
    fail "--max-redirs"
fi

# --- -u/--user basic auth ---
echo "--- -u/--user ---"
assert_stderr_contains "Basic" "-u basic auth" -u "user:pass" -v "$TEST_URL"

# --- -X/--request ---
echo "--- -X/--request ---"
assert_exit 0 "-X POST" -X POST -d "a=1" "$TEST_URL"
assert_exit 0 "-X PUT" -X PUT -d "a=1" "$TEST_URL"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
exit $FAIL
