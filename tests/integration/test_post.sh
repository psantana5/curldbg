#!/bin/bash
set +e
PORT=$1; BASE="http://127.0.0.1:$PORT"
CDBG="${CURLDBG_BIN:-./curldbg} -s"
PASS=0; FAIL=0

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

# --- POST request ---
BODY=$($CDBG -X POST "$BASE/echo" -o - 2>/dev/null)
assert_eq "POST echo" "posted" "$BODY"

# --- POST with body (-d) ---
assert_no_crash "POST-data" $CDBG -X POST -d "hello" "$BASE/echo" -o /dev/null 2>/dev/null

echo "post: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
