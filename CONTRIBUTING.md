# Contributing to curldbg

## Build

```
make              # release build with -O2 -Werror
make unit-test    # run unit tests
make unit-test-vg # unit tests under Valgrind
make unit-test-san # unit tests under ASan/UBSan
make unit-test-tsan # unit tests under TSan
make integration  # integration tests against testd + public HTTP/2 servers
make test         # full test: Valgrind + integration + fuzz (FUZZ_MAX_TIME, default 30s)
make test-san     # full test under ASan/UBSan
make test-tsan    # full test under TSan
make check        # test + test-san + test-tsan
make coverage     # LCOV coverage report (html in obj/coverage/)
make cppcheck     # static analysis
make fuzz-all     # build all fuzzers (requires clang)
make static       # statically-linked binary
make install PREFIX=/usr/local  # install to system
```

## Testing guidelines

- All PRs should pass `make check` before submission.
- New parse functions should have unit tests in `tests/unit.c`.
- New protocol handling (HTTP/2 frames, HPACK, chunked encoding) should have a fuzz target in `tests/fuzz_*.c`.
- Run the integration test suite if you change the request/response path: `make integration`.

## Coding conventions

- C99 dialect, compiled as `gcc` (also tested under `clang`).
- Warnings are errors (`-Werror`). Code must compile with all flags in `CFLAGS` (see `Makefile`).
- No `strcpy`, `strcat`, or `sprintf` — use `safe_strlcpy` or `snprintf`.
- Error-passing functions take `char *error, size_t error_len` and call `snprintf`.
- Always check the return value of `snprintf` (and every other fallible call);
  negative return or truncation is an error condition, not a warning.
- `goto` is used only for centralized cleanup: functions with multiple
  allocation sites use a single cleanup funnel (`goto error_cleanup` /
  `goto done`) so every exit path frees in one place. See `run.c` and
  `main.c` for the pattern.
- HTTP/2 ownership convention: a successfully allocated `struct h2_connection`
  stays attached to `conn->h2` on every path, including partial-init failures.
  Only `http2_cleanup()` frees it (and clears `conn->h2`); callers must never
  `free()` an h2 connection themselves. This exists because a double-free/UAF
  bug was fixed here — do not "optimize" it away.
- Frame payload validation is strict and consistent: control frames with
  fixed-size payloads (WINDOW_UPDATE = 4 octets, PING = 8, SETTINGS ACK =
  empty) are rejected as protocol errors when the size differs; see
  `src/net/http2/conn.c`, `request.c`, `response.c`.
- Headers use include guards `CURLDBG_<NAME>_H`.
- Forward-declare structs where possible to avoid circular includes.
- Commit messages use conventional-commit prefixes: `fix:`, `feat:`, `refactor:`, `ci:`, `chore:`, `test:`.
