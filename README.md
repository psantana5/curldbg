# curldbg

curldbg is a lightweight HTTP/HTTPS client that doubles as both a **debugging tool**
and a **curl-compatible CLI** for scripting. It speaks raw HTTP/1.1 over TLS, reports
per-request timing metrics, and handles real-world HTTP features like redirects,
chunked transfer encoding, and multi-value headers.

It was born from a practical need — during the Ubuntu mirrors outage on April 16
(`security.ubuntu.com`, `archive.ubuntu.com`), having quick low-level visibility
into DNS, TCP connect, and TTFB timing was essential for diagnosing what was
actually failing and where.

## Key capabilities

- **Request profiling** — per-hop DNS, TCP, TTFB, and total timing, with connected
  IP and address family for each hop
- **curl-compatible CLI** — supports common curl flags (`-d`, `-L`, `-f`, `-sS`,
  `-I`, `-A`, `-H`, `-u`, `-X`, `-o`, `-O`, `-T`, `-k`, `-4`/`-6`, `-v`,
  `--max-time`, `--connect-timeout`, `--read-timeout`, `--no-happy-eyeballs`) for
  drop-in use in scripts
- **Redirect following** — tracks the full redirect chain with per-hop timing
- **Post data from files/stdin** — `-d @file` and `-d @-` avoid shell escaping
- **Chunked decoding** — decodes chunked Transfer-Encoding on the fly so piped
  output (e.g. `curldbg ... | jq`) works transparently
- **Pipe auto-detect** — when stdout is not a TTY, auto-silences and writes raw
  body to stdout
- **Compare modes** — `--compare` (IPv4 vs IPv6) and `--compare-urls` (two URLs)
  run requests concurrently and show side-by-side metrics + deltas

## Use cases

- **Scripting** — replace `/usr/bin/curl` with a symlink to curldbg for a compatible
  CLI that handles JSON-RPC workflows (Zabbix API, etc.) with chunked encoding and
  pipe-friendly output
- **Network debugging** — quick visibility into DNS resolution, connect latency,
  TTFB, redirect chains, and happy-eyeballs races
- **Embedded/low-resource** — single ~62KB binary, no libcurl dependency, minimal
  memory footprint

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

- `src/main.c` — CLI option parsing, redirect loop, output formatting, test runner
- `src/curldbg.c` — networking, TLS, HTTP send/receive, chunked decoding, URL parsing
- `include/curldbg.h` — shared structs, constants, function declarations

## Testing

```bash
make test
```

Requires network access to httpbin.org.
