#!/bin/sh
# curldbg vs curl benchmark — 200 iterations per scenario
# Usage: sh tests/bench.sh

CURL="${CURL:-/home/sanpau/.local/curl-real/bin/curl}"
DBG="${DBG:-./curldbg}"
URL_SINGLE="https://httpbin.org/get"
URL_R1="https://httpbin.org/redirect/1"
URL_R5="https://httpbin.org/redirect/5"
N=${N:-200}

if [ ! -x "$CURL" ]; then echo "curl not found at $CURL"; exit 1; fi
if [ ! -x "$DBG" ]; then echo "curldbg not found at $DBG"; exit 1; fi

stats() {
  # reads numbers stdin, one per line → prints count mean median min max p95
  awk '
  {
    vals[NR] = $1
    sum += $1
  }
  END {
    n = NR
    if (n == 0) { print "0 0 0 0 0 0"; exit }
    mean = sum / n
    asort(vals)
    median = (n % 2 == 1) ? vals[(n+1)/2] : (vals[n/2] + vals[n/2+1]) / 2
    min = vals[1]
    max = vals[n]
    p95_idx = int(n * 0.95 + 0.5)
    if (p95_idx < 1) p95_idx = 1
    if (p95_idx > n) p95_idx = n
    p95 = vals[p95_idx]
    printf "n=%d  mean=%.2f  median=%.2f  min=%.2f  max=%.2f  p95=%.2f\n", n, mean, median, min, max, p95
  }'
}

bench_one() {
  local label="$1" url="$2" tool="$3" flags="$4"
  local tmpf=$(mktemp)
  for i in $(seq 1 $N); do
    if [ "$tool" = "curldbg" ]; then
      $DBG $flags -o /dev/null "$url" 2>/dev/null | grep "^Total:" | awk '{print $2}' >> "$tmpf"
    else
      $CURL $flags -o /dev/null -s -w "%{time_total}\n" "$url" 2>/dev/null >> "$tmpf"
    fi
  done
  # convert curl seconds → ms
  if [ "$tool" = "curl" ]; then
    awk '{print $1 * 1000}' "$tmpf" > "${tmpf}2" && mv "${tmpf}2" "$tmpf"
  fi
  local result=$(stats < "$tmpf")
  rm -f "$tmpf"
  printf "  %-10s %s\n" "$tool" "$result"
}

echo "=== WARMUP ==="
$DBG -sS -o /dev/null "$URL_SINGLE" 2>/dev/null

echo ""
echo "=== BENCHMARK: each test runs ${N} iterations ==="
echo ""

echo "1) SINGLE GET"
bench_one "" "$URL_SINGLE" "curldbg" ""
bench_one "" "$URL_SINGLE" "curl" ""

echo ""
echo "2) 1 REDIRECT"
bench_one "" "$URL_R1" "curldbg" "-L"
bench_one "" "$URL_R1" "curl" "-L"

echo ""
echo "3) 5 REDIRECTS (same host)"
bench_one "" "$URL_R5" "curldbg" "-L"
bench_one "" "$URL_R5" "curl" "-L"

echo ""
echo "4) SINGLE GET — NO HAPPY EYEBALLS"
bench_one "" "$URL_SINGLE" "curldbg" "--no-happy-eyeballs"
bench_one "" "$URL_SINGLE" "curl" "--happy-eyeballs-timeout-ms 0"

echo ""
echo "=== DONE ==="
