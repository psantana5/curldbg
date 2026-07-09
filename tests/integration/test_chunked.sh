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

# --- valid chunked ---
BODY=$($CDBG "$BASE/chunked" -o - 2>/dev/null | tr -d '\r')
assert_eq "chunked body" "Wikipedia in chunks." "$BODY"

# --- bad chunk: must not crash ---
assert_no_crash "bad-chunk" $CDBG "$BASE/bad-chunk" -o /dev/null 2>/dev/null

echo "chunked: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]