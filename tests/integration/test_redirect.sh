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

# --- /redirect/1 must not crash ---
assert_no_crash "/redirect/1" $CDBG -L "$BASE/redirect/1" -o /dev/null 2>/dev/null

# --- /redirect/3 ---
assert_no_crash "/redirect/3" $CDBG -L "$BASE/redirect/3" -o /dev/null 2>/dev/null

# --- /redirect/5 ---
assert_no_crash "/redirect/5" $CDBG -L "$BASE/redirect/5" -o /dev/null 2>/dev/null

# --- redirect loop ---
assert_no_crash "redirect-loop" $CDBG -L --max-redirs 3 "$BASE/redirect-loop" -o /dev/null 2>/dev/null

# --- infinite redirect ---
assert_no_crash "infinite-redirect" $CDBG -L --max-redirs 5 "$BASE/infinite-redirect" -o /dev/null 2>/dev/null

echo "redirect: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]