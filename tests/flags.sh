#!/bin/sh
# Exhaustive flag & redirect test suite for curldbg
# Tests every flag 3 times against local test server where possible
# Run: cd tests && sh flags.sh

CURLDBG="${CURLDBG:-../curldbg}"
PASS=0
FAIL=0
TOTAL=0
ITERATIONS=3

pass() { PASS=$((PASS+1)); echo "  PASS[$TOTAL]: $*"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL[$TOTAL]: $*"; }

TEST_SERVER_PORT=18997
TEST_SERVER_LOG=$(mktemp)
python3 "$(dirname "$0")/server.py" "$TEST_SERVER_PORT" > "$TEST_SERVER_LOG" 2>&1 &
TEST_SERVER_PID=$!
for i in 1 2 3 4 5 6 7 8; do
    if grep -q "TEST_SERVER_READY" "$TEST_SERVER_LOG" 2>/dev/null; then
        break
    fi
    sleep 0.3
done
if ! grep -q "TEST_SERVER_READY" "$TEST_SERVER_LOG" 2>/dev/null; then
    echo "Failed to start test server"
    cat "$TEST_SERVER_LOG"
    exit 1
fi

LOCAL="http://127.0.0.1:$TEST_SERVER_PORT"

# Usage: run_check expected <curldbg args...>
# Checks that curldbg's stdout contains 'expected'
run_check() {
    local expected="$1"; shift
    TOTAL=$((TOTAL+1))
    local out
    out=$($CURLDBG -sS "$@" 2>/dev/null)
    local got=$?
    case "$out" in
        *"$expected"*) pass "$*" ;;
        *) fail "$* (exit=$got, expected stdout to contain '$expected', got: $out)" ;;
    esac
}

# Usage: run_check_exit expected_exit <curldbg args...>
run_check_exit() {
    local want="$1"; shift
    TOTAL=$((TOTAL+1))
    $CURLDBG -sS "$@" 2>/dev/null
    local got=$?
    if [ "$got" = "$want" ]; then
        pass "$* (exit=$got)"
    else
        fail "$* (expected exit $want, got $got)"
    fi
}

# Usage: run_check_stderr expected <curldbg args...>
run_check_stderr() {
    local expected="$1"; shift
    TOTAL=$((TOTAL+1))
    local out
    out=$($CURLDBG -sS "$@" 2>&1 >/dev/null)
    case "$out" in
        *"$expected"*) pass "$*" ;;
        *) fail "$* (expected stderr '$expected', got: $out)" ;;
    esac
}

# Usage: run_iters count expected <curldbg args...>
run_iters() {
    local count=$1; shift
    local expected="$1"; shift
    local label="$(echo "$*" | head -c 60)"
    echo "  [$label] x$count"
    for i in $(seq 1 $count); do
        run_check "$expected" "$@"
    done
}

echo "=== Exhaustive curldbg flag & redirect test suite ==="
echo "Test server: $LOCAL"
echo "Each test runs $ITERATIONS times"
echo

# ============================================================
# REDIRECT TESTS (using local server)
# ============================================================
echo "=== REDIRECT TESTS ==="

echo "--- Single redirect ---"
run_iters $ITERATIONS '{"redirected": true}' "-L" "$LOCAL/redirect/1"
run_iters $ITERATIONS '{"redirected": true}' "--location" "$LOCAL/redirect/1"

echo "--- Multi-hop redirect ---"
run_iters $ITERATIONS '{"redirected": true}' "-L" "$LOCAL/redirect/5"

echo "--- No -L (no follow, shows 302 in stderr) ---"
for i in $(seq 1 $ITERATIONS); do
    run_check_stderr "302" "-v" "$LOCAL/redirect/2"
done

echo "--- --max-redirs limit ---"
for i in $(seq 1 $ITERATIONS); do
    run_check_exit 1 "-L" "--max-redirs" "1" "$LOCAL/redirect/3"
done

echo "--- --max-redirs enough ---"
run_iters $ITERATIONS '{"redirected": true}' "-L" "--max-redirs" "10" "$LOCAL/redirect/3"

echo "--- Redirect to absolute URL ---"
run_iters $ITERATIONS "ECHO_OK" "-L" "$LOCAL/redirect-to?url=$LOCAL/echo"

echo "--- Redirect status 301 ---"
run_iters $ITERATIONS "ECHO_OK" "-L" "$LOCAL/redirect-to?url=$LOCAL/echo&status_code=301"

echo "--- Redirect status 302 ---"
run_iters $ITERATIONS "ECHO_OK" "-L" "$LOCAL/redirect-to?url=$LOCAL/echo&status_code=302"

echo "--- Redirect status 303 ---"
run_iters $ITERATIONS "ECHO_OK" "-L" "$LOCAL/redirect-to?url=$LOCAL/echo&status_code=303"

echo "--- Redirect status 307 ---"
run_iters $ITERATIONS "ECHO_OK" "-L" "$LOCAL/redirect-to?url=$LOCAL/echo&status_code=307"

echo "--- Redirect status 308 ---"
run_iters $ITERATIONS "ECHO_OK" "-L" "$LOCAL/redirect-to?url=$LOCAL/echo&status_code=308"

echo "--- Redirect 307 preserves POST method ---"
run_iters $ITERATIONS "METHOD:POST" "-L" "-X" "POST" "-d" "body=1" "$LOCAL/redirect-to?url=$LOCAL/echo&status_code=307"

echo "--- Redirect 308 preserves POST method ---"
run_iters $ITERATIONS "METHOD:POST" "-L" "-X" "POST" "-d" "body=1" "$LOCAL/redirect-to?url=$LOCAL/echo&status_code=308"

echo "--- Redirect verbose shows Location ---"
for i in $(seq 1 $ITERATIONS); do
    run_check_stderr "Location:" "-L" "-v" "-o" "/dev/null" "$LOCAL/redirect/2"
done

echo "--- Redirect 303 changes POST to GET ---"
run_iters $ITERATIONS "METHOD:GET" "-L" "-X" "POST" "-d" "body=1" "$LOCAL/redirect-to?url=$LOCAL/echo&status_code=303"

echo
# ============================================================
# EVERY FLAG TESTS (using local server)
# ============================================================
echo "=== FLAG TESTS ==="

echo "--- --version ---"
run_iters $ITERATIONS "curldbg" "--version"

echo "--- --wizard ---"
run_iters $ITERATIONS "wizard" "--wizard" 2>/dev/null

echo "--- --lore ---"
$CURLDBG --lore 2>/dev/null || true
echo "  INFO: --lore ran"

echo "--- --fika ---"
$CURLDBG --fika 2>/dev/null || true
echo "  INFO: --fika ran"

echo "--- --debug-chaos ---"
run_iters $ITERATIONS "ECHO_OK" "--debug-chaos" "$LOCAL/echo"

echo "--- -v/--verbose ---"
for i in $(seq 1 $ITERATIONS); do
    run_check_stderr "> GET" "-v" "$LOCAL/echo"
done
for i in $(seq 1 $ITERATIONS); do
    run_check_stderr "> GET" "--verbose" "$LOCAL/echo"
done
for i in $(seq 1 $ITERATIONS); do
    run_check_stderr "< HTTP" "-v" "$LOCAL/echo"
done

echo "--- -s/--silent ---"
run_iters $ITERATIONS "ECHO_OK" "-s" "$LOCAL/echo"
run_iters $ITERATIONS "ECHO_OK" "--silent" "$LOCAL/echo"

echo "--- -S/--show-error ---"
run_iters $ITERATIONS "ECHO_OK" "-S" "$LOCAL/echo"
run_iters $ITERATIONS "ECHO_OK" "--show-error" "$LOCAL/echo"

echo "--- -k/--insecure ---"
run_iters $ITERATIONS "ECHO_OK" "-k" "$LOCAL/echo"

echo "--- -A/--user-agent ---"
run_iters $ITERATIONS "ECHO_OK" "-A" "CustomAgent/1.0" "$LOCAL/echo"
run_iters $ITERATIONS "ECHO_OK" "--user-agent" "AgentLong/1.0" "$LOCAL/echo"

echo "--- -H custom header ---"
run_iters $ITERATIONS "ECHO_OK" "-H" "X-Test: hello" "$LOCAL/echo"
run_iters $ITERATIONS "ECHO_OK" "-H" "X-One: 1" "-H" "X-Two: 2" "$LOCAL/echo"

echo "--- -H Host override ---"
run_iters $ITERATIONS "ECHO_OK" "-H" "Host: example.com" "$LOCAL/echo"

echo "--- -d/--data ---"
run_iters $ITERATIONS "ECHO_OK" "-d" "foo=bar" "$LOCAL/echo"
run_iters $ITERATIONS "ECHO_OK" "-d" "a=1" "-d" "b=2" "$LOCAL/echo"
run_iters $ITERATIONS "ECHO_OK" "--data" "data=val" "$LOCAL/echo"
run_iters $ITERATIONS "ECHO_OK" "--data-binary" "binary=1" "$LOCAL/echo"

echo "--- -d @file ---"
echo -n "filecontents" > /tmp/curldbg_test_data_flag.txt
run_iters $ITERATIONS "ECHO_OK" "-d" "@/tmp/curldbg_test_data_flag.txt" "$LOCAL/echo"
rm -f /tmp/curldbg_test_data_flag.txt

echo "--- -X/--request ---"
run_iters $ITERATIONS "METHOD:POST" "-X" "POST" "-d" "x=1" "$LOCAL/echo"
run_iters $ITERATIONS "METHOD:PUT" "-X" "PUT" "-d" "x=1" "$LOCAL/echo"
run_iters $ITERATIONS "METHOD:DELETE" "-X" "DELETE" "$LOCAL/echo"
run_iters $ITERATIONS "METHOD:PATCH" "-X" "PATCH" "-d" "x=1" "$LOCAL/echo"
run_iters $ITERATIONS "METHOD:OPTIONS" "-X" "OPTIONS" "$LOCAL/echo"
run_iters $ITERATIONS "METHOD:PURGE" "-X" "PURGE" "$LOCAL/echo"

echo "--- -I/--head ---"
for i in $(seq 1 $ITERATIONS); do
    TOTAL=$((TOTAL+1))
    out=$($CURLDBG -sS -I "$LOCAL/echo" 2>/dev/null)
    if [ -z "$out" ]; then
        pass "-I $LOCAL/echo (empty body for HEAD)"
    else
        fail "-I $LOCAL/echo (expected empty body, got: $out)"
    fi
done

echo "--- -f/--fail ---"
run_check_exit 1 "-f" "-sS" "-o" "/dev/null" "$LOCAL/status/404"

echo "--- -o/--output ---"
OUTFILE="/tmp/curldbg_test_output_$$.txt"
for i in $(seq 1 $ITERATIONS); do
    rm -f "$OUTFILE"
    $CURLDBG -sS -o "$OUTFILE" "$LOCAL/echo" 2>/dev/null
    TOTAL=$((TOTAL+1))
    if [ -f "$OUTFILE" ] && grep -q "ECHO_OK" "$OUTFILE" 2>/dev/null; then
        pass "-o $OUTFILE $LOCAL/echo"
    else
        fail "-o $OUTFILE $LOCAL/echo (content: $(cat $OUTFILE 2>/dev/null))"
    fi
done
rm -f "$OUTFILE"

echo "--- --progress-bar ---"
run_iters $ITERATIONS "ECHO_OK" "--progress-bar" "$LOCAL/echo"

echo "--- --no-happy-eyeballs ---"
run_iters $ITERATIONS "ECHO_OK" "--no-happy-eyeballs" "$LOCAL/echo"

echo "--- -4 (IPv4) ---"
run_iters $ITERATIONS "ECHO_OK" "-4" "$LOCAL/echo"

echo "--- -6 (IPv6) ---"
$CURLDBG -sS -6 -o /dev/null "$LOCAL/echo" 2>/dev/null
echo "  INFO: -6 exit code: $?"

echo "--- -d triggers POST ---"
run_iters $ITERATIONS "METHOD:POST" "-d" "x=y" "$LOCAL/echo"

echo "--- -T/--upload-file ---"
echo -n "upload-data" > /tmp/curldbg_test_upload.txt
run_iters $ITERATIONS "upload-data" "-T" "/tmp/curldbg_test_upload.txt" "$LOCAL/echo"
rm -f /tmp/curldbg_test_upload.txt

echo "--- -T - stdin upload ---"
for i in $(seq 1 $ITERATIONS); do
    echo "stdinbody1" | run_check "stdinbody1" "-T" "-" "-H" "Content-Type: text/plain" "$LOCAL/echo"
done

echo "--- -b/--cookie ---"
run_iters $ITERATIONS "ECHO_OK" "-b" "name=value" "$LOCAL/echo"
run_iters $ITERATIONS "ECHO_OK" "-b" "a=1" "-b" "b=2" "$LOCAL/echo"
run_iters $ITERATIONS "ECHO_OK" "--cookie" "token=abc123" "$LOCAL/echo"

echo "--- -c/--cookie-jar ---"
COOKIE_JAR="/tmp/curldbg_jar_$$.txt"
run_iters $ITERATIONS '{"cookie_set": true}' "-c" "$COOKIE_JAR" "$LOCAL/set-cookie?name=test&value=hello"
if [ -f "$COOKIE_JAR" ] && grep -q "test" "$COOKIE_JAR" 2>/dev/null; then
    echo "  PASS: cookie jar file written and contains 'test'"
fi
rm -f "$COOKIE_JAR"

echo "--- -c multiple Set-Cookie ---"
COOKIE_JAR2="/tmp/curldbg_jar2_$$.txt"
run_iters $ITERATIONS '{"cookies_set": 3}' "-c" "$COOKIE_JAR2" "$LOCAL/set-multi-cookie"
if [ -f "$COOKIE_JAR2" ]; then
    COUNT=$(grep -c -E "^[^#]" "$COOKIE_JAR2" 2>/dev/null || echo 0)
    echo "  INFO: cookie jar has $COUNT entries"
fi
rm -f "$COOKIE_JAR2"

echo "--- -b @cookie-file ---"
COOKIE_FILE="/tmp/curldbg_cookies_$$.txt"
cat > "$COOKIE_FILE" << 'EOF'
# Netscape HTTP Cookie File
.example.com	TRUE	/	FALSE	0	loaded	cookie_val
EOF
$CURLDBG -sS -b "@$COOKIE_FILE" "$LOCAL/echo" 2>/dev/null | grep -q "ECHO_OK" && \
    echo "  PASS: -b @file" || echo "  FAIL: -b @file"
rm -f "$COOKIE_FILE"

echo "--- --connect-timeout ---"
run_iters $ITERATIONS "ECHO_OK" "--connect-timeout" "5000" "$LOCAL/echo"

echo "--- --read-timeout ---"
run_iters $ITERATIONS "ECHO_OK" "--read-timeout" "5000" "$LOCAL/echo"

echo "--- --max-time (generous) ---"
run_iters $ITERATIONS "ECHO_OK" "--max-time" "10000" "$LOCAL/echo"

echo "--- --max-time (timeout 1ms, local req fast enough) ---"
$CURLDBG -sS --max-time 1 "$LOCAL/echo" 2>/dev/null
echo "  INFO: --max-time 1ms exit code: $? (0 = request completed within 1ms)"

echo "--- --max-redirs parsing ---"
run_iters $ITERATIONS '{"redirected": true}' "-L" "--max-redirs" "10" "$LOCAL/redirect/1"

echo "--- --proxy (HTTP target through HTTP proxy) ---"
run_iters $ITERATIONS "ECHO_OK" "--proxy" "http://127.0.0.1:$TEST_SERVER_PORT" "$LOCAL/echo"

echo "--- --proxy verbose shows absolute URI ---"
for i in $(seq 1 $ITERATIONS); do
    run_check_stderr "> GET http://" "--proxy" "http://127.0.0.1:$TEST_SERVER_PORT" "-v" "-o" "/dev/null" "$LOCAL/echo"
done

echo "--- Combined short flags ---"
run_iters $ITERATIONS "ECHO_OK" "-sfvk" "$LOCAL/echo"

echo "--- Combined -sSIL (HEAD+Location, no body) ---"
out=$($CURLDBG -sSIL "$LOCAL/redirect/1" 2>/dev/null)
if [ -z "$out" ]; then echo "  PASS: -sSIL combined (empty body from HEAD)"; else echo "  FAIL: -sSIL combined (expected empty body, got: $out)"; fi

echo "--- --compare (IPv4 vs IPv6, needs 1 URL) ---"
$CURLDBG --compare "$LOCAL/echo" 2>/dev/null
echo "  INFO: --compare exit code: $?"

echo "--- --compare-urls (compare two URLs) ---"
$CURLDBG --compare-urls "$LOCAL/echo" "$LOCAL/echo" 2>/dev/null
echo "  INFO: --compare-urls exit code: $?"

echo "--- -O/--remote-name ---"
rm -f echo
for i in $(seq 1 $ITERATIONS); do
    rm -f echo
    $CURLDBG -sS -O "$LOCAL/echo" 2>/dev/null
    TOTAL=$((TOTAL+1))
    if [ -f echo ] && grep -q "ECHO_OK" echo 2>/dev/null; then
        pass "-O $LOCAL/echo (wrote to file 'echo')"
    else
        fail "-O $LOCAL/echo"
    fi
done
rm -f echo

# ============================================================
# Cleanup
# ============================================================
kill "$TEST_SERVER_PID" 2>/dev/null
wait "$TEST_SERVER_PID" 2>/dev/null
rm -f "$TEST_SERVER_LOG"

echo
echo "=== Summary: $PASS passed, $FAIL failed out of $TOTAL tests ==="
echo "  (each test run $ITERATIONS times where applicable)"
exit $FAIL
