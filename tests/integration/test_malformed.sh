#!/bin/bash
set +e
PORT=$1; BASE="http://127.0.0.1:$PORT"
CDBG="${CURLDBG_BIN:-./curldbg} -s"
PASS=0; FAIL=0

assert_no_crash() {
    local label=$1; shift
    "$@" >/dev/null 2>&1
    if [ $? -le 1 ]; then ((PASS++))
    else echo "  FAIL [$label]: crashed (signal)"; ((FAIL++)); fi
}

assert_no_crash "lf-only"            $CDBG "$BASE/lf-only" -o /dev/null 2>/dev/null
assert_no_crash "double-cl"          $CDBG "$BASE/double-content-length" -o /dev/null 2>/dev/null
assert_no_crash "negative-cl"        $CDBG "$BASE/negative-content-length" -o /dev/null 2>/dev/null
assert_no_crash "empty-response"     $CDBG "$BASE/empty-response" -o /dev/null 2>/dev/null
assert_no_crash "close-after-hdrs"   $CDBG "$BASE/close-after-headers" -o /dev/null 2>/dev/null
assert_no_crash "partial-body"       $CDBG "$BASE/partial-body" -o /dev/null 2>/dev/null
assert_no_crash "premature-close"    $CDBG "$BASE/premature-close" -o /dev/null 2>/dev/null
assert_no_crash "large-header"       $CDBG "$BASE/large-header" -o - 2>/dev/null
assert_no_crash "infinite-redirect"  $CDBG -L --max-redirs 5 "$BASE/infinite-redirect" -o /dev/null 2>/dev/null
assert_no_crash "slow-header"        $CDBG --read-timeout 2000 "$BASE/slow-header" -o /dev/null 2>/dev/null
assert_no_crash "slow-body"          $CDBG --read-timeout 2000 "$BASE/slow-body" -o /dev/null 2>/dev/null

echo "malformed: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]