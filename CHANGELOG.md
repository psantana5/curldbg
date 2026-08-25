# Changelog

## [2.1.8]

### Fixed
- Reject WINDOW_UPDATE frames with payload not exactly 4 octets in the HTTP/2
  preface and response receive loops, matching the strict validation already
  applied in `http2_send_request`
- Check `hpack_table_add()` return value at its call site in
  `parse_h2_header_block()`; OOM during a dynamic-table insert now fails
  cleanly as a compression error instead of silently continuing with an
  inconsistent table
- Harden the overflow guard in `hpack_table_add()` so intermediate arithmetic
  cannot underflow when both name and value lengths are near SIZE_MAX

### Changed
- Consolidate `signal(SIGPIPE, SIG_IGN)` to `parse_cmdline()` only; removed
  the redundant copy from `main()`
- Document project conventions in CONTRIBUTING.md: checked snprintf returns,
  goto cleanup funnels, `conn->h2` ownership, and strict control-frame
  payload validation

## [2.1.7]

### Fixed
- WINDOW_UPDATE frames with a payload not exactly 4 octets are now rejected as
  a protocol error during request body send; previously oversized frames left
  extra bytes in the stream and desynced subsequent frame parsing (RFC 7540
  Section 6.4)

### Changed
- Fuzz time budget in `make test` is configurable via `FUZZ_MAX_TIME`
  (default 30s)
- New `--local-only` flag for tests/integration/run.sh skips the public
  HTTP/2 endpoint tests; the CI integration job uses it so CI no longer
  depends on external services

## [2.1.6]

### Fixed
- HPACK dynamic table size update instructions inside a header block are now
  rejected with a compression error when they exceed the advertised
  SETTINGS_HEADER_TABLE_SIZE cap (RFC 7540 Section 6.5.2); previously the
  SETTINGS path was clamped but the decoder path accepted any size up to 4 GB,
  letting a peer inflate client memory
- Remove provably dead `hpack_off <= length` bound check in HTTP/2 HEADERS
  handling (guaranteed by the PADDED/PRIORITY validation above it)
- README project tree now shows `include/` at the project root instead of
  nested under `src/`

### Added
- Unit tests: HPACK table size update clamping (within/above cap), HPACK
  encoder boundary sweep (output sizes 0-200 x name indexes x string lengths x
  integer prefixes, exact-size allocations for ASan redzones), and
  chunked-overrides-Content-Length policy (valid and malformed CL)
- CI: documentation-only commits now skip the heavy test jobs via a
  paths-filter gate; cppcheck still runs as the lightweight lint

### Changed
- cppcheck now scans all of `tests/` (fuzz drivers and unit.c) in addition to
  `src/`; fixed the const-correctness nits it surfaced
- Makefile documents that sanitizer builds intentionally omit hardening flags
- Fuzz targets fail fast with a clear error when clang is missing instead of
  an obscure compiler failure

## [2.1.5]

### Fixed
- Use-after-free/double-free: `conn->h2` is now cleared before `free(h2)` when
  the stream array allocation fails in `http2_init_connection`, so a subsequent
  `close_connection()` no longer dereferences freed memory
- HPACK dynamic table is now emptied when a single entry exceeds the maximum
  table size, per RFC 7541 Section 4.4 (previously the table was left untouched)
- Infinite loop in `hpack_table_add`: adding to a full dynamic table could hang
  forever because eviction guarded on `size > max_size`, a condition inserts can
  never produce; eviction now targets `max_size - entry_size` via a shared
  `hpack_table_evict_until()` helper

### Added
- Fuzz target `curldbg-fuzz-h2headers` exercising the stateful
  `parse_h2_header_block()` path (dynamic table, Huffman strings, table size
  updates); it found the eviction hang above
- Unit tests for oversized-entry table emptying and full-table eviction

### Changed
- Fuzz CI workflow no longer swallows crash exit codes with `|| true`; any
  non-zero fuzzer exit now fails the job (timeout safety cap still tolerated)

## [2.1.4]

### Changed
- Add `auto_buf` helper (stack/heap buffer with 8KB threshold) in `util.c/h`
- Convert `http2_send_request` to use `auto_buf`, eliminating 64KB stack allocation
- Document Linux/glibc dependency in README.md Requirements section
- Add `-fanalyzer` CI job and fuzz corpus caching in GitHub Actions workflows
- Add `-Isrc/net/http2` to `COMMON_CFLAGS` so all build variants can test internal http2 APIs

### Fixed
- Memory leak: `auto_buf` heap buffer now freed on all return paths in `http2_send_request`

### Added
- Unit tests for `h2_settings_apply` (8 tests) and `parse_h2_header_block` (4 tests)

## [2.1.3]

### Changed
- Modularize `src/net/http2.c` (1583 lines) into 9 files under `src/net/http2/`
  (frame, settings, stream, dyn_table, conn, headers, request, response, http2_internal.h)
- Simplify Makefile: unified build variants via `$(eval)` template, wildcard sources/headers,
  generalized fuzz targets, shared `WARN_FLAGS` across all build configurations
- Add new warning flags: `-Wformat=2 -Wnull-dereference -Wdouble-promotion -Wundef -Wstrict-prototypes`
- Add `analyze` and `clang-analyze` Makefile targets
- Move `hpack_encode_literal_without_indexing` from http2.c to src/net/hpack.c (public API)
- Deduplicate SETTINGS parsing into `h2_settings_apply()`

### Fixed
- Dead code in HTTP/2 connection preface (unreachable `!got_settings` check)
- Missing `__attribute__((format))` on format functions (caught by `-Wformat=2`)

## [2.1.2]

### Added
- Document all previously missing CLI flags in `man/curldbg.1` (`--data-urlencode`,
  `--referer`, `--write-out`, `--dump-header`, `--cacert`, `--capath`, `--tlsv1.2`,
  `--tlsv1.3`, `--retry`, `--retry-delay`, `--resolve`, `--interface`, `--unix-socket`,
  `--http1.1`, `--http2`, `--compressed`, `--help`, `--disable`, `--proto`,
  `--proto-redir`)

## [2.1.1]

### Fixed
- Response body now printed after timing output, with `Response:` label and separator

### Changed
- Body buffering uses dynamic allocation (realloc) capped at 100 MB with overflow protection

## [2.1.0]

### Added
- `-V` short flag for `--version`
- `VERSIONING` document specifying semver conventions and release checklist

### Changed
- Response body output now shows full content (was capped at first 1KB)
- Default User-Agent now uses `CURLDBG_VERSION` (`curldbg/2.1.0`) instead of hardcoded `curldbg/1.0`

### Removed
- `preview` buffer and `PREVIEW_BYTES` limit from response pipeline

## [2.0.15]

### Changed
- Default User-Agent now uses `CURLDBG_VERSION` (`curldbg/2.0.15`) instead of hardcoded `curldbg/1.0`

## [2.0.14]

### Added
- `-V` short flag for `--version`

## [2.0.13]

### Fixed
- HPACK decompression error when decoding empty Huffman-encoded header values

## [2.0.12]

### Added
- `--proto` flag as curl compatibility no-op
- `--proto-redir` flag as curl compatibility no-op
- `-D`/`--dump-header` flag to write response headers to a file

### Fixed
- `make clean` now removes fuzz binaries, static binary, and `gmon.out`

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
