# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in curldbg, please report it to
**<pau.santana.gh@gmail.com>**. Do not open a public issue.

We aim to acknowledge reports within 48 hours and provide an initial assessment
within one week.

## Supported versions

Only the latest release is supported for security fixes. The version is
defined in `include/version.h`.

## Design

curldbg is an HTTP/HTTPS debugging client. It parses untrusted input from
remote servers (HTTP headers, HTTP/2 frames, HPACK-compressed blocks, chunked
transfer-encoded bodies, gzip streams). The following defenses are in place:

- All network-input parsers (HTTP/1.1 response headers, HTTP/2 frames, HPACK
  decode, chunked decoder, gzip inflation) are bounds-checked and exercised
  under ASan/UBSan in CI.
- Huffman and HPACK decoders are fuzzed nightly.
- No unsafe string functions (`strcpy`/`strcat`/`sprintf`) exist in the
  codebase. All bounded copies use `safe_strlcpy` or `snprintf`.
- TLS verifies certificates by default (`SSL_VERIFY_PEER` + hostname check).
  The `-k`/`--insecure` flag explicitly disables verification.
- CRLF injection in user-supplied header values is rejected at parse time.
- File upload size is checked against `SIZE_MAX` to prevent integer truncation
  from `off_t` to `size_t`.

## Known limitations

- No stack canaries beyond `-fstack-protector-strong` and
  `-fstack-clash-protection` provided by compiler flags.
- Fuzzing runs nightly at 60 seconds per target, not continuously.
- Cookie jar loading silently truncates lines exceeding 8 KB.
- Release binaries are not GPG-signed or SLSA-provenanced.
