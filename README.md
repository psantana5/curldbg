# curldbg

`curldbg` is a tiny HTTP/HTTPS request debugger written in C. It performs a single GET/POST request and prints request lifecycle timing:

- DNS lookup
- TCP connect
- TTFB (time to first byte)
- Total request time

It also prints:

- Redirect chain (with `-L`)
- Per-hop timing (DNS/TCP/TTFB)
- Connected IP + family (IPv4/IPv6) per hop
- Optional "Other" raced endpoint line when Happy Eyeballs captures a loser candidate
- Final resolved URL (after redirects, when `-L` is used)
- A small preview of the response body (about 1 KB)

## Why this exists

This tool came from a real troubleshooting idea during the Ubuntu mirrors outage on **April 16** (notably around `security.ubuntu.com` and `archive.ubuntu.com`), where quick low-level timing visibility was useful for debugging network and mirror behavior.

## Build

```bash
make
```

Project layout:

- `src/main.c` - CLI flow, redirect loop, and output formatting
- `src/curldbg.c` - networking, TLS, HTTP I/O, parsing, and timing helpers
- `include/curldbg.h` - shared structs, constants, and function declarations

## Usage

```bash
./curldbg <url>
./curldbg google.com # bare hosts default to https://
./curldbg -L <url>   # follow redirects
./curldbg -4 <url>   # force IPv4
./curldbg -6 <url>   # force IPv6
./curldbg -X GET <url>
./curldbg -X POST -d "k=v&x=1" <url>
./curldbg -X PUT -T ./file.bin <url>
./curldbg --connect-timeout 3000 --read-timeout 5000 <url>
./curldbg -L --max-redirs 20 <url>
./curldbg --compare -L -X POST -d "a=1" <url>         # compare IPv4 vs IPv6 for one URL
./curldbg --compare-urls -X GET <url-a> <url-b>       # compare two URLs side-by-side
./curldbg -sS -O <url>                                # save body to remote filename
./curldbg -k -u user:pass -H "Accept: application/json" <url>
./curldbg -v -H "Content-Type: application/json" -d '{"key":"value"}' <url>
./curldbg -d @file.json <url>                          # read POST data from file
./curldbg -d @- <url>                                  # read POST data from stdin
./curldbg -d "a=1" -d "b=2" <url>                     # multiple -d concatenate with &
./curldbg --data-binary @file.bin <url>                # binary POST data alias
./curldbg --version
```

Flags:

- `--compare` run the same URL twice (IPv4 vs IPv6) and print diffs
- `--compare-urls` run two URL requests and print side-by-side metrics + deltas
- `-X, --request <GET|POST|PUT>` choose HTTP method
- `-d, --data <body>` request body data (defaults method to POST if `-X` is not set); `@file` reads from file, `@-` reads from stdin; repeatable — values concatenate with `&`
- `--data-binary` alias for `-d`
- `-v, --verbose` show request headers (`> `) and response headers (`< `) on stderr
- `-f, --fail` exit non-zero on HTTP status >= 400 (no body output)
- `-L` follow redirects
- `-s, --silent` suppress normal output
- `-S, --show-error` show errors when used with `-s`
- `-k, --insecure` skip TLS certificate verification
- `-u, --user <user:pass>` use HTTP Basic auth
- `-H, --header <header>` add a request header (repeatable); providing `Content-Type` or `Content-Length` skips auto-generation
- `-4` force IPv4 DNS/connect
- `-6` force IPv6 DNS/connect
- `-o, --output <file>` write response body to file (single request mode only)
- `-O, --remote-name` write response body using the URL filename (single request mode only)
- `-T, --upload-file <file>` upload file as the PUT request body (single request mode only)
- `--connect-timeout <ms>` timeout per connect attempt
- `--read-timeout <ms>` timeout for read/write operations
- `--no-happy-eyeballs` disable Happy Eyeballs and connect sequentially
- `--max-redirs <n>` maximum redirects when `-L` is enabled (default: 10)
- `--version` show version and author

`--compare` and `--compare-urls` both reuse the same request path as normal mode, then compare: DNS, TCP, TTFB, total, final status, connected IP/family, and final URL.
Both compare modes run the two profiles concurrently to reduce total wall-clock time.

When URL scheme is omitted (for example `google.com`), `curldbg` defaults to `https://`.

When stdout is not a TTY (piped or redirected), `curldbg` automatically silences normal output and writes the raw response body to stdout. Use `-S` to still see errors.

By default (`auto` family), connect uses a Happy Eyeballs style strategy: IPv6 is attempted first, then IPv4 is started shortly after to reduce dual-stack stalls.
