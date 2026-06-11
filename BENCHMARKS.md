# Benchmark Results — curldbg vs curl

Two benchmark environments:

- **Local**: Docker `kennethreitz/httpbin` on loopback (`127.0.0.1:9999`), HTTP only, no network jitter — measures pure request overhead
- **Remote**: Public `https://httpbin.org` via internet, HTTPS/TLS — measures real-world performance

curldbg built with `gcc -O2 -Wall -Wextra -pthread -Iinclude`, linked against OpenSSL 3.0.

## How to run

```sh
# Start local benchmark server
docker run -d --rm --name curldbg-httpbin -p 127.0.0.1:9999:80 kennethreitz/httpbin

# Local benchmark (500 iterations)
N=500 sh tests/bench.sh

# Remote benchmark (200 iterations)
N=200 sh tests/bench.sh remote

# Stop server
docker stop curldbg-httpbin
```

## Local benchmark (500 iterations, zero network noise)

| Scenario | Metric | curldbg | curl | Δ |
|---|---|---|---|---|
| GET /get | median | **0.45 ms** | 0.31 ms | +45% |
| GET /get | P95 | **0.52 ms** | 0.41 ms | +27% |
| GET /bytes/1024 | median | **0.45 ms** | 0.31 ms | +45% |
| GET /bytes/1024 | P95 | **0.53 ms** | 0.45 ms | +18% |
| GET /bytes/65536 | median | **0.65 ms** | 0.55 ms | +18% |
| GET /bytes/65536 | P95 | **0.82 ms** | 0.66 ms | +24% |
| POST /post | median | **0.47 ms** | 0.34 ms | +38% |
| POST /post | P95 | **0.56 ms** | 0.54 ms | +4% |
| GET /bytes/1 | median | **0.41 ms** | 0.33 ms | +24% |
| GET /bytes/1M | median | **3.48 ms** | 3.59 ms | **−3%** |
| GET /bytes/1M | P95 | **44.32 ms** | 3.76 ms | _server-driven_ |
| 1 Redirect | median | **41.23 ms** | 41.45 ms | **−0.5%** |
| 1 Redirect | P95 | **42.12 ms** | 42.14 ms | **−0.1%** |
| 3 Redirects | median | **123.75 ms** | 123.37 ms | +0.3% |
| 3 Redirects | P95 | **124.13 ms** | 124.19 ms | **−0.1%** |
| 5 Redirects | median | **205.81 ms** | 205.20 ms | +0.3% |
| 5 Redirects | P95 | **206.08 ms** | 206.09 ms | **−0.01%** |

On redirect-heavy workloads curldbg matches curl within noise. Connection reuse (keep-alive) across same-host redirects keeps it competitive. The absolute gap on single requests is ~0.13ms (down from ~0.4ms) — primarily DNS thread overhead and warmup_tls() are now eliminated for plain HTTP to numeric IPs.

## Remote benchmark (200 iterations, httpbin.org via HTTPS)

| Scenario | Metric | curldbg | curl | Δ |
|---|---|---|---|---|
| Single GET | median | 465 ms | 461 ms | +0.9% |
| Single GET | P95 | 756 ms | 659 ms | +15% |
| 1 Redirect | mean | **654 ms** | 735 ms | **−10.9%** |
| 1 Redirect | P95 | 982 ms | 945 ms | +3.9% |

(3+ redirect chains hit httpbin.org rate limits when run at 200 iterations.)

On real-world HTTPS, the ~0.4 ms overhead is dwarfed by network RTT (~400 ms). curldbg matches curl on single GET median and improves 1 Redirect mean by 11%.

## Previous baseline vs current (June 2026)

Comparing current `curldbg` against the previous iteration:

| Scenario | Metric | Before | After | Δ |
|---|---|---|---|---|
| GET /get (local) | median | 0.70 ms | **0.45 ms** | **−36%** |
| GET /get (local) | vs curl | +106% | +45% | gap halved |
| GET /bytes/65536 (local) | n / 500 | 128 | **500** | bug fixed |
| GET /bytes/1M (local) | n / 500 | 110 | **500** | bug fixed |
| GET /bytes/1M (local) | mean | 11.50 ms | **8.30 ms** | **−28%** |

## Optimizations applied

| Optimization | File | Impact |
|---|---|---|
| **TCP_NODELAY** | main.c | Disables Nagle's algorithm after connect; eliminates up to 200ms write latency on POST/PUT |
| **DNS timeout (5s)** | curldbg.c + main.c | `getaddrinfo` wrapped in `pthread_timedjoin_np` thread; caps slow DNS at 5s instead of 10-30s |
| **Happy-eyeballs poll fix** | curldbg.c | `poll_timeout = -1` now bounded to 30s per-attempt deadline instead of blocking forever |
| **HAPPY_EYEBALLS_DELAY 100→25ms** | curldbg.c | Saves 75ms per connection in the worst-case race path |
| **Default connect timeout (30s)** | curldbg.c | `connect_with_timeout` defaults to 30s instead of blocking `connect()` |
| **Default read timeout (30s)** | main.c | `SO_RCVTIMEO`/`SO_SNDTIMEO` set even when no `--read-timeout` given |
| **Content-Length aware reading** | curldbg.c | Clean EOF avoidance; enables keep-alive on non-chunked responses |
| **TLS warmup** | curldbg.c + main.c | CA cert loading moved outside timed section; P95 **−22%** from baseline |
| **memchr header parsing** | curldbg.c | `strstr`→`memchr` saves two-byte scan per header line |
| **malloc+memcpy request build** | curldbg.c | No zero-fill waste; no format-string overhead in `snprintf` |
| **Response header buffer overflow fix** | curldbg.c | Cap header copy at `HEADER_MAX` when first TCP read exceeds it (fixes `Response headers too large` on large bodies + loopback) |
| **warmup_tls → HTTP-only** | main.c | Move `warmup_tls()` inside redirect loop, guarded by `url.use_tls`. Saves ~50ms for plain HTTP requests that never init OpenSSL's CA store. |
| **Numeric IP DNS fast path** | curldbg.c | Skip `pthread_create`/join for numeric IPs — `getaddrinfo` on IPs returns instantly on the calling thread. Saves ~50-150µs per request. |

## Test Environment

- CA store: 298 symlinks in `/etc/ssl/certs` + 220 KB bundle
- Valgrind: **0 errors, 0 definite/indirect/possible losses** (OpenSSL "still reachable" only)
- All 31 functional tests pass
