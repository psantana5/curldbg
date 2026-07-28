# curldbg

[![CI](https://github.com/psantana5/curldbg/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/psantana5/curldbg/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-report-blue)](https://github.com/psantana5/curldbg/actions/workflows/ci.yml)

curldbg is a lightweight HTTP/HTTPS client that doubles as both a **debugging tool**
and a **curl-inspired CLI** for scripting. It speaks HTTP/1.1 and HTTP/2 over TLS,
reports per-request timing metrics, and handles real-world HTTP features like
redirects, chunked transfer encoding, gzip decompression, and cookie jars.

It was born from a practical need — during the Ubuntu mirrors outage on April 16
(`security.ubuntu.com`, `archive.ubuntu.com`), having quick low-level visibility
into DNS, TCP connect, and TTFB timing was essential for diagnosing what was
actually failing and where.

> **Note:** curldbg is not a complete curl replacement. It supports a subset of
curl's most common flags. Review the flag list below before using it in existing
scripts.

## Key capabilities

- **HTTP/2** — full multiplexing with per-stream flow control, HPACK header
  compression, ALPN negotiation, and graceful GOAWAY shutdown
- **Request profiling** — per-hop DNS, TCP, TTFB, and total timing, with connected
  IP and address family for each hop
- **curl-inspired CLI** — supports common curl flags (`-d`, `-L`, `-f`, `-sS`,
  `-I`, `-A`, `-H`, `-u`, `-X`, `-o`, `-O`, `-T`, `-k`, `-4`/`-6`, `-v`,
  `-b`/`-c`, `-e`, `-w`, `--proxy`, `--max-time`, `--connect-timeout`,
  `--read-timeout`, `--max-redirs`, `--compressed`, `--data-urlencode`,
  `--resolve`, `--interface`, `--tlsv1.2`, `--tlsv1.3`, `--retry`,
  `--retry-delay`, `--cacert`, `--capath`, `--unix-socket`, `--no-happy-eyeballs`)
  for scripting where only these features are needed
- **Redirect following** — tracks the full redirect chain with per-hop timing,
  301/302/303/307/308, with correct 303 GET-downgrade behavior
- **Post data from files/stdin** — `-d @file` and `-d @-` avoid shell escaping;
  `--data-urlencode` for URL-encoded form data
- **Chunked decoding** — decodes chunked Transfer-Encoding on the fly so piped
  output (e.g. `curldbg ... | jq`) works transparently
- **Gzip/deflate decompression** — `--compressed` transparently decompresses
  Content-Encoding: gzip/deflate
- **Pipe auto-detect** — when stdout is not a TTY, auto-silences and writes raw
  body to stdout
- **Compare modes** — `--compare` (IPv4 vs IPv6) and `--compare-urls` (two URLs)
  run requests concurrently and show side-by-side metrics + deltas
- **Multi-URL** — pass multiple URLs as positional arguments for batch requests
- **`--write-out`** — supports `%{http_code}`, `%{http_version}`, `%{time_total}`,
  `%{time_namelookup}`, `%{time_connect}`, `%{time_starttransfer}`,
  `%{url_effective}`, `%{num_redirects}`, `%{redirect_url}`

## Use cases

- **Scripting** — use curldbg in scripts that only need the supported subset of
  curl flags; verify compatibility before swapping it in for existing curl calls
- **Network debugging** — quick visibility into DNS resolution, connect latency,
  TTFB, redirect chains, and happy-eyeballs races
- **Embedded/low-resource** — single ~96KB binary, no libcurl dependency, minimal
  memory footprint

Performance measurements and methodology are documented in the [GitHub Wiki](https://github.com/psantana5/curldbg/wiki/Performance).

## Quick start

```bash
make
./curldbg https://example.com
./curldbg -L https://httpbin.org/redirect/3
./curldbg -X POST -d '{"json":"rpc"}' -H 'Content-Type: application/json' https://api.example.com
```

## Full flag reference

See `man ./man/curldbg.1` or `man curldbg` after install.

## Project layout

```
src/
├── main.c                   — main loop, output mode selection
├── run.c                     — request lifecycle, redirects, retries, connection orchestration
├── results.c                — output formatting for single, compare, and hop-level results
├── output.c                 — --write-out format string expansion
├── url.c                    — URL parsing, redirect URL construction, IPv6 bracket handling
├── cookie.c                 — Cookie jar for -b/-c flags, Netscape-format persistence
├── util.c                   — Timers, base64, URL encoding, error helpers
├── compare.c                — --compare (IPv4 vs IPv6) and --compare-urls modes
├── net/
│   ├── connect.c            — TCP connection, Happy Eyeballs (RFC 8305), Unix sockets, socket I/O
│   ├── dns.c                — DNS resolution with thread-based timeout, per-session DNS cache with TTL, resolve helpers
│   ├── tls.c                — TLS handshake via OpenSSL, session-scoped SSL_CTX, SNI, cert verification
│   ├── http2.c              — HTTP/2: stream multiplexing, frame dispatch, HPACK, flow control
│   └── proxy.c              — HTTP CONNECT proxy handshake
├── http/
│   ├── request.c            — HTTP/1.1 request building and sending
│   └── response.c           — HTTP/1.1 response receive, header parsing, chunked decoding, gzip/deflate
├── cli/
│   ├── parse.c              — CLI option parsing with error returns, combined flags (-sfvk), signal setup
│   └── help.c               — --help flag rendering
└── include/
    ├── curldbg.h            — shared structs, constants, function declarations
    └── flags.h              — flag definitions table
```

## Testing

```bash
make test
```

Builds and runs the internal unit-test suite under Valgrind.
