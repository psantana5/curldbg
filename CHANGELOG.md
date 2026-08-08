# Changelog

## [2.0.11]

### Changed
- `run_request()` refactored: extracted `build_request_headers`, `dispatch_request`, `update_hop_record`, and `plan_redirect` into independently-testable functions
- Replaced `goto reconnect` retry with an explicit inner `for(;;)` loop — at-most-one-retry-per-hop is now structural, not goto-based

### Fixed
- Stale `conn->last_errno` now cleared on fresh connection establishment, preventing spurious retries on version-mismatch errors after a prior-hop transient failure

## [2.0.10]

### Changed
- Cookie jar entries allocated on demand (doubling capacity up to `MAX_COOKIES`) instead of a fixed 256-slot array (~1.4 MB) — empty jars are now 16 bytes
- Integration runner reports skipped tests separately; `CURLDBG_STRICT_SKIP=1` (set in CI) fails the build if any test is skipped

### Added
- `tests/server/requirements.txt` documents the `h2` dependency for the local HTTP/2 test server

### Fixed
- HTTP/2 integration test no longer silently skips: it exits with a distinct status and prints install instructions when the `h2` library is unavailable
- Removed stray comment and unified CLI error reporting in `main.c`
- Signed integer overflow in response status-code parsing (`parse_response_headers`) caught by UBSan — now bounds-checked without undefined behavior
- HPACK fuzzer speed regression (~100 exec/s, `-max_total_time` ignored): restructured to exercise `hpack_decode_int` and `huffman_decode` independently (~85k exec/s, `-max_total_time` works)
- Fuzzers now use `timeout` as a hard safety cap (some libFuzzer+ASan builds ignore `-max_total_time`) and `-entropic=0` for consistent throughput

## [2.0.9]

### Fixed
- `--max-time` and `--connect-timeout` now accept seconds instead of milliseconds (curl compat)

## [2.0.8]

### Added
- `-q`/`--disable` flag as curl compatibility no-op

## [2.0.7]

### Fixed
- DNS and TCP connect timing now displayed on connection failure (was incorrectly 0.00 ms)

## [2.0.6]

### Changed
- Precomputed Huffman decode tree as static array (no runtime allocation)
- Dynamic HTTP/2 stream allocation (pointer instead of fixed array)
- Lazy TLS context creation: SSL_CTX created only on first HTTPS connection

### Performance
- HTTP/1.1 localhost: **4.3 ms** (was 18.4 ms, 4.3× faster, now beats curl)
- Instructions per H1 request: **1.2M** (was 200M+, 167× fewer)

## [2.0.5]

### Added
- `--http1.1` and `--http2` flags to force protocol version

### Changed
- Deduplicated name/value extraction in `parse_h2_header_block()` via `decode_h2_header_name_value()`
- Release notes now pulled from `CHANGELOG.md` instead of static template
- Coverage: restored integration tests for accurate measurement, no threshold

### Fixed
- `cookie_jar_load()` skips truncated lines exceeding 8 KB

## [2.0.4]

### Fixed
- Body preview no longer leaked to stderr when `-o` writes to a file

## [2.0.3]

### Added
- `CONTRIBUTING.md`, `SECURITY.md`
- `-fcf-protection=full -fstack-clash-protection` to default CFLAGS
- UBSan (`-fsanitize=undefined`) added to fuzz build flags
- CI concurrency group: cancels in-progress runs on new pushes

### Changed
- Deduplicated `parse_h2_header_block()`: extracted common validation into `apply_h2_header()`
- `handle_int_flag()` helper replaces 5 duplicated integer-flag handlers in `parse.c`
- `chunked_write()` uses `uint64_t`/`strtoull` instead of `unsigned long`/`strtoul`
- Removed dead BSD `#endif` branch in `http2.c` (Linux-only per project scope)

### Fixed
- cppcheck `constVariablePointer` in `parse.c:130`
- cppcheck `constParameterPointer` for `h2` in `apply_h2_header()`

## [2.0.2]

### Added
- CI-gated release workflow: checks commit status via GitHub API before publishing
- Nightly fuzz CI (cron at 6am UTC): 4 fuzzers × 60 seconds
- Fuzz targets: URL parser, Huffman decoder, HPACK decode (via `hpack_decode_string_ext`)

### Changed
- HPACK/Huffman code extracted to standalone `src/net/hpack.c` (no networking dependencies)
- CLI flag table (`include/flags.h`) now drives `parse_cmdline` via `find_flag()`/`handle_flag()` dispatch (single source of truth)
- `parse_cmdline` broken up: `handle_flag()` (~200 lines, flag-specific), `validate_cmdline_opts()` (~40 lines, extracted from `main()`)
- CRLF injection validation centralized into `validate_no_crlf()` (was 11 inline checks)
- CI: removed unused `workflow_call:`, removed redundant `latest` forward-compat job
- Release workflow: `check-ci` job gates on CI status; removed test re-runs

### Fixed
- Clang `-Wsign-conversion` in HPACK SETTINGS parsing (cast `unsigned char` to `uint32_t` before shift)
- `--version`/`--help` returning incorrect exit code after table-driven dispatch refactoring
- Makefile static build uses `-l:libssl.a` / `-l:libcrypto.a` (portable static linkage)

## [2.0.1]

### Added
- Huffman round-trip unit test
- `safe_strlcpy()` inline helper

### Fixed
- Huffman encoder: correct bit-accumulation algorithm
- All `strcpy()` calls replaced with `safe_strlcpy()`
- Dead condition: `request_retried` initialization moved before `reconnect:` label
- Const-discard in `run.c`
- glibc 2.41+ `strchr` const-discard build breaker

### Changed
- `http2_receive_response` split: `parse_h2_header_block()`, `handle_h2_data_frame()` extracted
- CFLAGS: `-Wconversion -Wsign-conversion -Wpedantic` enabled on default build
- CI: pinned to `ubuntu-24.04`
- Version bumped to 2.0.1

## [2.0.0]

### Added
- HTTP/2 support: full multiplexing, HPACK header compression (Huffman encode/decode), ALPN negotiation, GOAWAY shutdown
- Happy Eyeballs (RFC 8305) dual-stack connect racing
- `--resolve` flag for custom DNS resolution
- `--unix-socket` flag
- DNS TTL cache with pthread mutex
- 174 unit tests, 9 integration test scripts
- CI: Valgrind, ASan/UBSan, TSan, clang, cppcheck, coverage

## [1.4.0]

### Added
- Initial release: HTTP/1.1 client with curl-compatible CLI
- Redirect following with per-hop timing
- Compare modes (`--compare`, `--compare-urls`)
- Chunked transfer decoding, gzip/deflate decompression
- Cookie jar with Netscape format save/load
