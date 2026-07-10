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

# --- gzip body ---
BODY=$($CDBG --compressed "$BASE/gzip" -o - 2>/dev/null)
assert_eq "gzip decompress" "hello from gzip" "$BODY"

# --- gzip without --compressed (raw bytes) ---
assert_no_crash "gzip-no-compress" $CDBG "$BASE/gzip" -o /dev/null 2>/dev/null

echo "gzip: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
