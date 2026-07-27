#!/bin/bash
set +e
PORT=$1; BASE="http://127.0.0.1:$PORT"
CDBG="${CURLDBG_BIN:-./curldbg}"
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

assert_exit_code() {
    local label=$1 expected=$2; shift 2
    "$@" >/dev/null 2>&1
    local rc=$?
    if [ "$rc" = "$expected" ]; then ((PASS++))
    else echo "  FAIL [$label]: expected exit $expected, got $rc"; ((FAIL++)); fi
}

# --- sanity: /redirect/3 -> final 200 ---
rc=$($CDBG -s -L -o /dev/null -w '%{http_code}' "$BASE/redirect/3" 2>/dev/null)
assert_eq "/redirect/3 → status" "200" "$rc"

# --- final URL after redirect ---
url=$($CDBG -s -L -o /dev/null -w '%{url_effective}' "$BASE/redirect/3" 2>/dev/null)
assert_eq "/redirect/3 → final_url" "$BASE/final" "$url"

# --- %{redirect_url} outputs the full URL (not just hostname) ---
# Without -L, /redirect/3 returns 302 → /redirect/2
ru=$($CDBG -s -o /dev/null -w '%{redirect_url}' "$BASE/redirect/3" 2>/dev/null)
assert_eq "/redirect/3 → redirect_url" "$BASE/redirect/2" "$ru"

# --- redirect-loop with --max-redirs 3 fails ---
assert_exit_code "redirect-loop limited" 1 $CDBG -s -L --max-redirs 3 "$BASE/redirect-loop" -o /dev/null 2>/dev/null

# --- infinite redirect with --max-redirs 5 fails ---
assert_exit_code "infinite-redirect limited" 1 $CDBG -s -L --max-redirs 5 "$BASE/infinite-redirect" -o /dev/null 2>/dev/null

# --- /redirect/1 must not crash ---
assert_no_crash "/redirect/1" $CDBG -s -L "$BASE/redirect/1" -o /dev/null 2>/dev/null

# --- /redirect/5 ---
assert_no_crash "/redirect/5" $CDBG -s -L "$BASE/redirect/5" -o /dev/null 2>/dev/null

echo "redirect: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
