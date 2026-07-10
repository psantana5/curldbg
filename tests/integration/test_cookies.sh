#!/bin/bash
set +e
PORT=$1; BASE="http://127.0.0.1:$PORT"
CDBG="${CURLDBG_BIN:-./curldbg} -s"
PASS=0; FAIL=0
JAR=/tmp/curldbg_test_jars.$$.txt

assert_eq() {
    local label=$1 expected=$2 actual=$3
    if [ "$actual" = "$expected" ]; then ((PASS++))
    else echo "  FAIL [$label]: expected '$expected', got '$actual'"; ((FAIL++)); fi
}

assert_no_crash() {
    local label=$1; shift
    "$@" >/dev/null 2>&1
    if [ $? -le 1 ]; then ((PASS++))
    else echo "  FAIL [$label]: crashed (signal)"; ((FAIL++)); fi
}

rm -f "$JAR"

# --- save cookies to jar ---
$CDBG -c "$JAR" "$BASE/cookies" -o /dev/null 2>/dev/null
assert_eq "cookie jar created" "0" "$(test -f "$JAR" && echo 0 || echo 1)"

# --- verify cookie content ---
MATCHES=$(grep -c "session.*abc123" "$JAR" 2>/dev/null)
assert_eq "session cookie saved" "1" "$MATCHES"

# --- load cookies and make request ---
assert_no_crash "cookie load" $CDBG -b "@$JAR" "$BASE/" -o /dev/null 2>/dev/null

rm -f "$JAR"
echo "cookies: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
