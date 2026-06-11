#!/bin/sh
# curldbg vs curl benchmark
# Usage:
#   sh tests/bench.sh                     # local (bench server or Docker)
#   sh tests/bench.sh remote              # public httpbin.org (rate-limited)
#   BENCH_HOST=192.168.1.92:9999 sh tests/bench.sh   # custom host
#
# Environment:
#   N           iterations (default: 500)
#   CURL        path to real curl binary
#   DBG         path to curldbg binary
#   BENCH_HOST  target host:port

CURL="${CURL:-/home/sanpau/.local/curl-real/bin/curl}"
DBG="${DBG:-./curldbg}"

[ ! -x "$CURL" ] && { echo "curl not found at $CURL"; exit 1; }
[ ! -x "$DBG" ]  && { echo "curldbg not found at $DBG"; exit 1; }

# Determine target
MODE="${1:-local}"
if [ -n "$BENCH_HOST" ]; then
    SCHEME="${BENCH_TLS:+https}${BENCH_TLS:-http}"
    BASE="${SCHEME}://$BENCH_HOST"
    LABEL=" ($BENCH_HOST)"
elif [ "$MODE" = "remote" ]; then
    BASE="https://httpbin.org"
    LABEL=" (remote httpbin.org)"
else
    BASE="http://127.0.0.1:9999"
    LABEL=" (local)"
fi

N=${N:-500}
WARMED=false

echo "=== WARMUP ==="
$DBG -sS -o /dev/null "$BASE/get" 2>/dev/null && WARMED=true
echo ""

echo "=== BENCHMARK${LABEL}: ${N} iterations ==="
echo ""

stats() {
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
  local name="$1" url="$2" tool="$3" flags="$4" iters="$5"
  local tmpf=$(mktemp)
  local i
  iters=${iters:-$N}
  for i in $(seq 1 $iters); do
    if [ "$tool" = "curldbg" ]; then
      $DBG $flags -o /dev/null "$url" 2>/dev/null | grep -a "^Total:" | awk '{print $2}' >> "$tmpf"
    else
      $CURL $flags -o /dev/null -s -w "%{time_total}\n" "$url" 2>/dev/null >> "$tmpf"
    fi
  done
  if [ "$tool" = "curl" ]; then
    awk '{print $1 * 1000}' "$tmpf" > "${tmpf}2" && mv "${tmpf}2" "$tmpf"
  fi
  local result=$(stats < "$tmpf")
  rm -f "$tmpf"
  printf "  %-20s %-8s %s\n" "$name" "$tool" "$result"
}

# Fast scenarios (N iterations each)
echo "--- GET requests ---"
bench_one "GET /get"             "$BASE/get"               "curldbg" ""
bench_one "GET /get"             "$BASE/get"               "curl"    ""
bench_one "GET /bytes/1024"      "$BASE/bytes/1024"        "curldbg" ""
bench_one "GET /bytes/1024"      "$BASE/bytes/1024"        "curl"    ""
bench_one "GET /bytes/65536"     "$BASE/bytes/65536"       "curldbg" ""
bench_one "GET /bytes/65536"     "$BASE/bytes/65536"       "curl"    ""
echo ""

echo "--- Redirection chain ---"
bench_one "1 Redirect"           "$BASE/redirect/1"        "curldbg" "-L"
bench_one "1 Redirect"           "$BASE/redirect/1"        "curl"    "-L"
bench_one "3 Redirects"          "$BASE/redirect/3"        "curldbg" "-L"
bench_one "3 Redirects"          "$BASE/redirect/3"        "curl"    "-L"
bench_one "5 Redirects"          "$BASE/redirect/5"        "curldbg" "-L"
bench_one "5 Redirects"          "$BASE/redirect/5"        "curl"    "-L"
echo ""

echo "--- POST ---"
bench_one "POST /post"           "$BASE/post"              "curldbg" "-X POST -d test"
bench_one "POST /post"           "$BASE/post"              "curl"    "-X POST -d test"
echo ""

echo "--- No Happy Eyeballs ---"
bench_one "No HE /get"           "$BASE/get"               "curldbg" "--no-happy-eyeballs"
bench_one "No HE /get"           "$BASE/get"               "curl"    "--happy-eyeballs-timeout-ms 0"
bench_one "No HE /redirect/1"    "$BASE/redirect/1"        "curldbg" "-L --no-happy-eyeballs"
bench_one "No HE /redirect/1"    "$BASE/redirect/1"        "curl"    "-L --happy-eyeballs-timeout-ms 0"
echo ""

echo "--- Response size scaling ---"
bench_one "GET /bytes/1"         "$BASE/bytes/1"           "curldbg" ""
bench_one "GET /bytes/1"         "$BASE/bytes/1"           "curl"    ""
bench_one "GET /bytes/1M"        "$BASE/bytes/1048576"     "curldbg" ""
bench_one "GET /bytes/1M"        "$BASE/bytes/1048576"     "curl"    ""
echo ""

echo "--- Slow scenarios (reduced iters) ---"
bench_one "GET /delay/0.2"       "$BASE/delay/0.2"         "curldbg" "" 20
bench_one "GET /delay/0.2"       "$BASE/delay/0.2"         "curl"    "" 20

echo ""
echo "=== DONE ==="
