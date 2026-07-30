# Changelog

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
