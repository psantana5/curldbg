#!/bin/bash
set +e
PORT=$1; BASE="http://127.0.0.1:$PORT"
CDBG="./curldbg -s"
PASS=0; FAIL=0

assert_eq() {
    local label=$1 expected=$2 actual=$3
    if [ "$actual" = "$expected" ]; then ((PASS++))
    else echo "  FAIL [$label]: expected '$expected', got '$actual'"; ((FAIL++)); fi
}

# --- / returns body ---
BODY=$($CDBG "$BASE/" -o - 2>/dev/null)
assert_eq "/ body" "hello from testd" "$BODY"

# --- /404 returns status 404 ---
STATUS=$($CDBG "$BASE/404" -o /dev/null -w "%{http_code}" 2>/dev/null)
assert_eq "/404 status" "404" "$STATUS"

# --- /500 returns status 500 ---
STATUS=$($CDBG "$BASE/500" -o /dev/null -w "%{http_code}" 2>/dev/null)
assert_eq "/500 status" "500" "$STATUS"

echo "basic: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]