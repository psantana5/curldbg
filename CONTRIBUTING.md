# Contributing to curldbg

## Build

```
make              # release build with -O2 -Werror
make unit-test    # run unit tests
make unit-test-vg # unit tests under Valgrind
make unit-test-san # unit tests under ASan/UBSan
make unit-test-tsan # unit tests under TSan
make integration  # integration tests against testd + public HTTP/2 servers
make test         # full test: Valgrind + integration + fuzz (30s)
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
- `goto` is used only for centralized cleanup (`goto cleanup` in `main.c`).
- Headers use include guards `CURLDBG_<NAME>_H`.
- Forward-declare structs where possible to avoid circular includes.
- Commit messages use conventional-commit prefixes: `fix:`, `feat:`, `refactor:`, `ci:`, `chore:`, `test:`.
