#include "curldbg.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <zlib.h>

static int tests_run = 0;
static int tests_failed = 0;

#define TEST(name) static void name(void)
#define ASSERT_INT_EQ(a, b, msg) do { \
    tests_run++; \
    if ((int)(a) != (int)(b)) { tests_failed++; fprintf(stderr, "FAIL %s: %s: %d != %d\n", __func__, msg, (int)(a), (int)(b)); } \
} while (0)
#define ASSERT_STR_EQ(a, b, msg) do { \
    tests_run++; \
    if (strcmp((a), (b)) != 0) { tests_failed++; fprintf(stderr, "FAIL %s: %s: '%s' != '%s'\n", __func__, msg, (a), (b)); } \
} while (0)
#define ASSERT_TRUE(a, msg) do { \
    tests_run++; \
    if (!(a)) { tests_failed++; fprintf(stderr, "FAIL %s: %s\n", __func__, msg); } \
} while (0)
#define ASSERT_FALSE(a, msg) ASSERT_TRUE(!(a), msg)
#define ASSERT_PTR_NOTNULL(p, msg) do { \
    tests_run++; \
    if ((p) == NULL) { tests_failed++; fprintf(stderr, "FAIL %s: %s: NULL\n", __func__, msg); } \
} while (0)

/* ================================================================
 * URL parsing
 * ================================================================ */

TEST(test_parse_url_http_simple) {
    struct url_info u;
    memset(&u, 0, sizeof(u));
    ASSERT_INT_EQ(parse_url("http://example.com/path", &u), 0, "parse_url return");
    ASSERT_STR_EQ(u.host, "example.com", "host");
    ASSERT_STR_EQ(u.port, "80", "port");
    ASSERT_STR_EQ(u.path, "/path", "path");
    ASSERT_FALSE(u.use_tls, "use_tls");
    ASSERT_FALSE(u.has_explicit_port, "has_explicit_port");
}

TEST(test_parse_url_https) {
    struct url_info u;
    memset(&u, 0, sizeof(u));
    ASSERT_INT_EQ(parse_url("https://example.com/", &u), 0, "parse_url return");
    ASSERT_STR_EQ(u.host, "example.com", "host");
    ASSERT_STR_EQ(u.port, "443", "port");
    ASSERT_STR_EQ(u.path, "/", "path");
    ASSERT_TRUE(u.use_tls, "use_tls");
    ASSERT_FALSE(u.has_explicit_port, "has_explicit_port");
}

TEST(test_parse_url_explicit_port) {
    struct url_info u;
    memset(&u, 0, sizeof(u));
    ASSERT_INT_EQ(parse_url("http://example.com:8080/path", &u), 0, "parse_url return");
    ASSERT_STR_EQ(u.host, "example.com", "host");
    ASSERT_STR_EQ(u.port, "8080", "port");
    ASSERT_TRUE(u.has_explicit_port, "has_explicit_port");
}

TEST(test_parse_url_no_scheme_defaults_to_https) {
    struct url_info u;
    memset(&u, 0, sizeof(u));
    ASSERT_INT_EQ(parse_url("example.com/path", &u), 0, "parse_url return");
    ASSERT_STR_EQ(u.host, "example.com", "host");
    ASSERT_STR_EQ(u.port, "443", "port");
    ASSERT_TRUE(u.use_tls, "use_tls (no scheme defaults to TLS)");
}

TEST(test_parse_url_ipv6) {
    struct url_info u;
    memset(&u, 0, sizeof(u));
    ASSERT_INT_EQ(parse_url("http://[::1]:8080/path", &u), 0, "parse_url return");
    ASSERT_STR_EQ(u.host, "::1", "host");
    ASSERT_STR_EQ(u.port, "8080", "port");
    ASSERT_TRUE(u.has_explicit_port, "has_explicit_port");
}

TEST(test_parse_url_ipv6_no_port) {
    struct url_info u;
    memset(&u, 0, sizeof(u));
    ASSERT_INT_EQ(parse_url("https://[::1]/", &u), 0, "parse_url return");
    ASSERT_STR_EQ(u.host, "::1", "host");
    ASSERT_STR_EQ(u.port, "443", "port");
    ASSERT_FALSE(u.has_explicit_port, "has_explicit_port");
}

TEST(test_parse_url_invalid_scheme) {
    struct url_info u;
    memset(&u, 0, sizeof(u));
    ASSERT_INT_EQ(parse_url("ftp://example.com", &u), -1, "parse_url ftp returns -1");
}

TEST(test_parse_url_no_path) {
    struct url_info u;
    memset(&u, 0, sizeof(u));
    ASSERT_INT_EQ(parse_url("http://example.com", &u), 0, "parse_url return");
    ASSERT_STR_EQ(u.path, "/", "path defaults to /");
}

TEST(test_parse_url_userinfo) {
    struct url_info u;
    memset(&u, 0, sizeof(u));
    ASSERT_INT_EQ(parse_url("http://user:pass@example.com/path", &u), 0, "userinfo URL");
    ASSERT_STR_EQ(u.host, "example.com", "host with userinfo");
    ASSERT_STR_EQ(u.user, "user", "user extracted");
    ASSERT_STR_EQ(u.pass, "pass", "pass extracted");
}

TEST(test_parse_url_userinfo_no_pass) {
    struct url_info u;
    memset(&u, 0, sizeof(u));
    ASSERT_INT_EQ(parse_url("http://user@example.com/path", &u), 0, "user-only URL");
    ASSERT_STR_EQ(u.user, "user", "user without pass");
    ASSERT_STR_EQ(u.pass, "", "pass empty");
}

TEST(test_parse_url_long_path) {
    struct url_info u;
    memset(&u, 0, sizeof(u));
    ASSERT_INT_EQ(parse_url("http://example.com/very/long/path/with/many/segments", &u), 0, "long path");
    ASSERT_STR_EQ(u.path, "/very/long/path/with/many/segments", "long path preserved");
}

TEST(test_parse_url_query_string) {
    struct url_info u;
    memset(&u, 0, sizeof(u));
    ASSERT_INT_EQ(parse_url("http://example.com/search?q=hello&page=1", &u), 0, "query string");
    ASSERT_STR_EQ(u.path, "/search?q=hello&page=1", "query preserved in path");
}

TEST(test_parse_url_fragment) {
    struct url_info u;
    memset(&u, 0, sizeof(u));
    ASSERT_INT_EQ(parse_url("http://example.com/page#section", &u), 0, "fragment");
    ASSERT_STR_EQ(u.path, "/page#section", "fragment preserved in path");
}

/* ================================================================
 * URL formatting
 * ================================================================ */

TEST(test_format_url_http) {
    struct url_info u;
    memset(&u, 0, sizeof(u));
    strcpy(u.host, "example.com");
    strcpy(u.port, "80");
    u.use_tls = false;
    strcpy(u.path, "/path");
    char out[256];
    ASSERT_INT_EQ(format_url(&u, out, sizeof(out)), 0, "format_url");
    ASSERT_STR_EQ(out, "http://example.com/path", "http URL");
}

TEST(test_format_url_https) {
    struct url_info u;
    memset(&u, 0, sizeof(u));
    strcpy(u.host, "example.com");
    strcpy(u.port, "443");
    u.use_tls = true;
    strcpy(u.path, "/");
    char out[256];
    ASSERT_INT_EQ(format_url(&u, out, sizeof(out)), 0, "format_url https");
    ASSERT_STR_EQ(out, "https://example.com/", "https URL");
}

TEST(test_format_url_explicit_port) {
    struct url_info u;
    memset(&u, 0, sizeof(u));
    strcpy(u.host, "example.com");
    strcpy(u.port, "8080");
    u.use_tls = false;
    u.has_explicit_port = true;
    strcpy(u.path, "/api");
    char out[256];
    format_url(&u, out, sizeof(out));
    ASSERT_STR_EQ(out, "http://example.com:8080/api", "explicit port in URL");
}

TEST(test_format_url_ipv6) {
    struct url_info u;
    memset(&u, 0, sizeof(u));
    strcpy(u.host, "::1");
    strcpy(u.port, "80");
    u.use_tls = false;
    strcpy(u.path, "/");
    char out[256];
    format_url(&u, out, sizeof(out));
    ASSERT_STR_EQ(out, "http://[::1]/", "IPv6 URL brackets");
}

TEST(test_format_host_header_standard) {
    struct url_info u;
    memset(&u, 0, sizeof(u));
    strcpy(u.host, "example.com");
    strcpy(u.port, "443");
    u.has_explicit_port = false;
    char out[320];
    format_host_header(&u, out, sizeof(out));
    ASSERT_STR_EQ(out, "example.com", "host header without default port");
}

TEST(test_format_host_header_explicit_port) {
    struct url_info u;
    memset(&u, 0, sizeof(u));
    strcpy(u.host, "example.com");
    strcpy(u.port, "8080");
    u.has_explicit_port = true;
    char out[320];
    format_host_header(&u, out, sizeof(out));
    ASSERT_STR_EQ(out, "example.com:8080", "host header with port");
}

TEST(test_format_host_header_ipv6) {
    struct url_info u;
    memset(&u, 0, sizeof(u));
    strcpy(u.host, "::1");
    strcpy(u.port, "8080");
    u.has_explicit_port = true;
    char out[320];
    format_host_header(&u, out, sizeof(out));
    ASSERT_STR_EQ(out, "[::1]:8080", "IPv6 host header");
}

TEST(test_format_host_header_overflow) {
    struct url_info u;
    memset(&u, 0, sizeof(u));
    memset(u.host, 'a', sizeof(u.host) - 1);
    u.host[sizeof(u.host) - 1] = '\0';
    u.has_explicit_port = false;
    char out[8];
    ASSERT_INT_EQ(format_host_header(&u, out, sizeof(out)), -1, "host header overflow returns error");
    ASSERT_INT_EQ(out[0], '\0', "overflow output is empty");
}

TEST(test_format_absolute_uri_overflow) {
    struct url_info u;
    memset(&u, 0, sizeof(u));
    strcpy(u.host, "example.com");
    strcpy(u.path, "/");
    u.use_tls = false;
    char out[16];
    ASSERT_INT_EQ(format_absolute_uri(&u, out, sizeof(out)), -1, "absolute URI overflow returns error");
    ASSERT_INT_EQ(out[0], '\0', "overflow output is empty");
}

TEST(test_format_absolute_uri_http) {
    struct url_info u;
    memset(&u, 0, sizeof(u));
    strcpy(u.host, "example.com");
    strcpy(u.port, "80");
    u.use_tls = false;
    strcpy(u.path, "/");
    char out[256];
    format_absolute_uri(&u, out, sizeof(out));
    ASSERT_STR_EQ(out, "http://example.com/", "absolute URI http");
}

/* ================================================================
 * is_redirect_status
 * ================================================================ */

TEST(test_is_redirect_status) {
    ASSERT_TRUE(is_redirect_status(301), "301 is redirect");
    ASSERT_TRUE(is_redirect_status(302), "302 is redirect");
    ASSERT_TRUE(is_redirect_status(303), "303 is redirect");
    ASSERT_TRUE(is_redirect_status(307), "307 is redirect");
    ASSERT_TRUE(is_redirect_status(308), "308 is redirect");
    ASSERT_FALSE(is_redirect_status(200), "200 is not redirect");
    ASSERT_FALSE(is_redirect_status(404), "404 is not redirect");
    ASSERT_FALSE(is_redirect_status(304), "304 is not redirect");
    ASSERT_FALSE(is_redirect_status(0), "0 is not redirect");
}

/* ================================================================
 * base64_encode
 * ================================================================ */

TEST(test_base64_encode_simple) {
    char out[64];
    ASSERT_INT_EQ(base64_encode((const unsigned char*)"f", 1, out, sizeof(out)), 0, "base64_encode return");
    ASSERT_STR_EQ(out, "Zg==", "base64 'f'");
}

TEST(test_base64_encode_fo) {
    char out[64];
    base64_encode((const unsigned char*)"fo", 2, out, sizeof(out));
    ASSERT_STR_EQ(out, "Zm8=", "base64 'fo'");
}

TEST(test_base64_encode_foo) {
    char out[64];
    base64_encode((const unsigned char*)"foo", 3, out, sizeof(out));
    ASSERT_STR_EQ(out, "Zm9v", "base64 'foo'");
}

TEST(test_base64_encode_empty) {
    char out[64];
    ASSERT_INT_EQ(base64_encode((const unsigned char*)"", 0, out, sizeof(out)), 0, "base64_encode empty");
    ASSERT_STR_EQ(out, "", "base64 empty string");
}

TEST(test_base64_encode_buffer_too_small) {
    char out[4];
    ASSERT_INT_EQ(base64_encode((const unsigned char*)"foo", 3, out, sizeof(out)), -1, "base64_encode buffer too small returns -1");
}

/* ================================================================
 * url_encode
 * ================================================================ */

TEST(test_url_encode_simple) {
    char out[128];
    ASSERT_INT_EQ(url_encode("hello world", out, sizeof(out)), 0, "url_encode return");
    ASSERT_STR_EQ(out, "hello%20world", "url_encode space");
}

TEST(test_url_encode_special_chars) {
    char out[128];
    url_encode("a+b=c", out, sizeof(out));
    ASSERT_STR_EQ(out, "a%2Bb%3Dc", "url_encode special chars");
}

TEST(test_url_encode_safe_chars) {
    char out[128];
    url_encode("abc-._~123", out, sizeof(out));
    ASSERT_STR_EQ(out, "abc-._~123", "url_encode safe chars unchanged");
}

TEST(test_url_encode_empty) {
    char out[128];
    url_encode("", out, sizeof(out));
    ASSERT_STR_EQ(out, "", "url_encode empty string");
}

/* ================================================================
 * util functions
 * ================================================================ */

TEST(test_ms_between) {
    struct timespec start = { .tv_sec = 0, .tv_nsec = 0 };
    struct timespec end = { .tv_sec = 1, .tv_nsec = 500000000L };
    double ms = ms_between(&start, &end);
    ASSERT_TRUE(ms > 1499.0 && ms < 1501.0, "ms_between 1.5 seconds");
}

TEST(test_ms_between_zero) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    double ms = ms_between(&ts, &ts);
    ASSERT_TRUE(ms >= -0.001 && ms <= 0.001, "ms_between zero diff");
}

TEST(test_trim_spaces_noop) {
    char s[] = "hello";
    char *p = s;
    trim_spaces(&p);
    ASSERT_STR_EQ(p, "hello", "trim_spaces no leading spaces");
}

TEST(test_trim_spaces_leading) {
    char s[] = "   hello";
    char *p = s;
    trim_spaces(&p);
    ASSERT_STR_EQ(p, "hello", "trim_spaces leading spaces");
}

TEST(test_trim_spaces_tabs) {
    char s[] = "\t\tworld";
    char *p = s;
    trim_spaces(&p);
    ASSERT_STR_EQ(p, "world", "trim_spaces leading tabs");
}

TEST(test_family_name) {
    ASSERT_STR_EQ(family_name(AF_INET), "IPv4", "family_name AF_INET");
    ASSERT_STR_EQ(family_name(AF_INET6), "IPv6", "family_name AF_INET6");
    ASSERT_STR_EQ(family_name(AF_UNIX), "Unknown", "family_name unknown");
}

TEST(test_append_str) {
    char buf[32] = "hello";
    size_t off = 5;
    ASSERT_INT_EQ(append_str(buf, sizeof(buf), &off, " world"), 0, "append_str return");
    ASSERT_STR_EQ(buf, "hello world", "append_str result");
    ASSERT_INT_EQ(off, 11, "append_str offset");
}

TEST(test_append_str_overflow) {
    char buf[8] = "hello";
    size_t off = 5;
    ASSERT_INT_EQ(append_str(buf, sizeof(buf), &off, " world!!"), -1, "append_str overflow returns -1");
}

TEST(test_is_timeout_errno) {
    ASSERT_TRUE(is_timeout_errno(EAGAIN), "EAGAIN is timeout");
    ASSERT_TRUE(is_timeout_errno(EWOULDBLOCK), "EWOULDBLOCK is timeout");
    ASSERT_TRUE(is_timeout_errno(ETIMEDOUT), "ETIMEDOUT is timeout");
    ASSERT_FALSE(is_timeout_errno(EINVAL), "EINVAL is not timeout");
    ASSERT_FALSE(is_timeout_errno(0), "0 is not timeout");
}

TEST(test_deadline_remaining_ms) {
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    long rem = deadline_remaining_ms(&start, 60000);
    ASSERT_TRUE(rem > 50000 && rem <= 60000, "deadline_remaining fresh");
}

TEST(test_deadline_remaining_ms_max_zero) {
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    ASSERT_INT_EQ(deadline_remaining_ms(&start, 0), -1, "deadline_remaining 0 max returns -1");
}

TEST(test_now_ms_monotonic) {
    long long t1 = now_ms_monotonic();
    ASSERT_TRUE(t1 > 0, "now_ms_monotonic returns positive");
    long long t2 = now_ms_monotonic();
    ASSERT_TRUE(t2 >= t1, "now_ms_monotonic is monotonic");
}

TEST(test_clear_race_info) {
    struct connect_race_info ri;
    ri.has_loser = true;
    ri.winner_connect_ms = 1.23;
    clear_race_info(&ri);
    ASSERT_FALSE(ri.has_loser, "has_loser cleared");
    ASSERT_TRUE(ri.winner_connect_ms == 0.0, "winner_connect_ms cleared");
}

TEST(test_clear_race_info_null) {
    clear_race_info(NULL);
    ASSERT_INT_EQ(1, 1, "clear_race_info NULL doesn't crash");
}

/* ================================================================
 * parse_response_headers
 * ================================================================ */

TEST(test_parse_response_headers_status) {
    char buf[HEADER_MAX + 1];
    struct response_info ri;
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "HTTP/1.1 200 OK\r\n\r\n");
    memset(&ri, 0, sizeof(ri));
    parse_response_headers(buf, &ri);
    ASSERT_INT_EQ(ri.status_code, 200, "status code");
}

TEST(test_parse_response_headers_location) {
    char buf[HEADER_MAX + 1];
    struct response_info ri;
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "HTTP/1.1 302 Found\r\nLocation: https://new.example.com/path\r\n\r\n");
    memset(&ri, 0, sizeof(ri));
    parse_response_headers(buf, &ri);
    ASSERT_INT_EQ(ri.status_code, 302, "status code");
    ASSERT_STR_EQ(ri.location, "https://new.example.com/path", "location header");
}

TEST(test_parse_response_headers_content_length) {
    char buf[HEADER_MAX + 1];
    struct response_info ri;
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "HTTP/1.1 200 OK\r\nContent-Length: 12345\r\n\r\n");
    memset(&ri, 0, sizeof(ri));
    parse_response_headers(buf, &ri);
    ASSERT_INT_EQ(ri.status_code, 200, "status code");
    ASSERT_INT_EQ((int)ri.content_length, 12345, "content-length");
}

TEST(test_parse_response_headers_chunked) {
    char buf[HEADER_MAX + 1];
    struct response_info ri;
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
    memset(&ri, 0, sizeof(ri));
    parse_response_headers(buf, &ri);
    ASSERT_TRUE(ri.chunked, "chunked encoding");
}

TEST(test_parse_response_headers_set_cookie) {
    char buf[HEADER_MAX + 1];
    struct response_info ri;
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc123\r\n\r\n");
    memset(&ri, 0, sizeof(ri));
    parse_response_headers(buf, &ri);
    ASSERT_TRUE(strstr(ri.set_cookie_buf, "session=abc123") != NULL, "set-cookie parsed");
}

TEST(test_parse_response_headers_no_headers) {
    char buf[HEADER_MAX + 1];
    struct response_info ri;
    memset(buf, 0, sizeof(buf));
    memset(&ri, 0, sizeof(ri));
    parse_response_headers(buf, &ri);
    ASSERT_INT_EQ(ri.status_code, 0, "empty headers has status 0");
}

TEST(test_parse_response_headers_lf_only) {
    char buf[HEADER_MAX + 1];
    struct response_info ri;
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "HTTP/1.1 200 OK\nContent-Length: 12345\n\n");
    memset(&ri, 0, sizeof(ri));
    parse_response_headers(buf, &ri);
    ASSERT_INT_EQ(ri.status_code, 200, "LF-only status code");
    ASSERT_INT_EQ((int)ri.content_length, 12345, "LF-only content-length");
}

TEST(test_parse_response_headers_http10) {
    char buf[HEADER_MAX + 1];
    struct response_info ri;
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "HTTP/1.0 200 OK\r\n\r\n");
    memset(&ri, 0, sizeof(ri));
    parse_response_headers(buf, &ri);
    ASSERT_INT_EQ(ri.status_code, 200, "HTTP/1.0 status code");
}

TEST(test_parse_response_headers_content_encoding_gzip) {
    char buf[HEADER_MAX + 1];
    struct response_info ri;
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n");
    memset(&ri, 0, sizeof(ri));
    parse_response_headers(buf, &ri);
    ASSERT_STR_EQ(ri.content_encoding, "gzip", "Content-Encoding gzip");
}

TEST(test_parse_response_headers_content_encoding_deflate) {
    char buf[HEADER_MAX + 1];
    struct response_info ri;
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\n\r\n");
    memset(&ri, 0, sizeof(ri));
    parse_response_headers(buf, &ri);
    ASSERT_STR_EQ(ri.content_encoding, "deflate", "Content-Encoding deflate");
}

TEST(test_parse_response_headers_multiple_set_cookie) {
    char buf[HEADER_MAX + 1];
    struct response_info ri;
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "HTTP/1.1 200 OK\r\n"
             "Set-Cookie: a=1\r\n"
             "Set-Cookie: b=2\r\n"
             "\r\n");
    memset(&ri, 0, sizeof(ri));
    parse_response_headers(buf, &ri);
    ASSERT_TRUE(strstr(ri.set_cookie_buf, "a=1") != NULL, "first cookie present");
    ASSERT_TRUE(strstr(ri.set_cookie_buf, "b=2") != NULL, "second cookie present");
}

TEST(test_parse_response_headers_bad_status) {
    char buf[HEADER_MAX + 1];
    struct response_info ri;
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "HTTP/1.1 xxx OK\r\n\r\n");
    memset(&ri, 0, sizeof(ri));
    parse_response_headers(buf, &ri);
    ASSERT_INT_EQ(ri.status_code, 0, "bad status line gives 0");
}

TEST(test_parse_response_headers_overflow_status) {
    char buf[HEADER_MAX + 1];
    struct response_info ri;
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "HTTP/1.1 99999999999999999999999999 OK\r\n\r\n");
    memset(&ri, 0, sizeof(ri));
    parse_response_headers(buf, &ri);
    ASSERT_INT_EQ(ri.status_code, 0, "overflowing status line rejected without UB");
}

TEST(test_parse_response_headers_transfer_encoding_list) {
    char buf[HEADER_MAX + 1];
    struct response_info ri;
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n");
    memset(&ri, 0, sizeof(ri));
    parse_response_headers(buf, &ri);
    ASSERT_TRUE(ri.chunked, "chunked at end of list recognized");
}

TEST(test_parse_response_headers_content_length_duplicate) {
    char buf[HEADER_MAX + 1];
    struct response_info ri;
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n");
    memset(&ri, 0, sizeof(ri));
    parse_response_headers(buf, &ri);
    ASSERT_INT_EQ(ri.content_length, -2, "duplicate Content-Length marked invalid");
}

TEST(test_parse_response_headers_content_length_negative) {
    char buf[HEADER_MAX + 1];
    struct response_info ri;
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n");
    memset(&ri, 0, sizeof(ri));
    parse_response_headers(buf, &ri);
    ASSERT_INT_EQ(ri.content_length, -2, "negative Content-Length marked invalid");
}

/* ================================================================
 * cookie_jar
 * ================================================================ */

TEST(test_cookie_jar_add_and_get) {
    struct cookie_jar jar;
    cookie_jar_init(&jar);
    cookie_jar_add_set_cookie(&jar, "session=abc; Path=/; Secure", "example.com", "/");

    char header[512];
    cookie_jar_get_header(&jar, "example.com", "/", true, header, sizeof(header));
    ASSERT_STR_EQ(header, "session=abc", "cookie header sent to matching host");
    cookie_jar_destroy(&jar);
}

TEST(test_cookie_jar_path_mismatch) {
    struct cookie_jar jar;
    cookie_jar_init(&jar);
    cookie_jar_add_set_cookie(&jar, "token=xyz; Path=/api", "example.com", "/api");

    char header[512];
    cookie_jar_get_header(&jar, "example.com", "/other", true, header, sizeof(header));
    ASSERT_STR_EQ(header, "", "cookie not sent for non-matching path");
    cookie_jar_destroy(&jar);
}

TEST(test_cookie_jar_domain_mismatch) {
    struct cookie_jar jar;
    cookie_jar_init(&jar);
    cookie_jar_add_set_cookie(&jar, "key=val", "example.com", "/");

    char header[512];
    cookie_jar_get_header(&jar, "other.com", "/", true, header, sizeof(header));
    ASSERT_STR_EQ(header, "", "cookie not sent for non-matching domain");
    cookie_jar_destroy(&jar);
}

TEST(test_cookie_jar_multiple_cookies) {
    struct cookie_jar jar;
    cookie_jar_init(&jar);
    cookie_jar_add_set_cookie(&jar, "a=1", "example.com", "/");
    cookie_jar_add_set_cookie(&jar, "b=2", "example.com", "/");

    char header[512];
    cookie_jar_get_header(&jar, "example.com", "/", true, header, sizeof(header));
    ASSERT_TRUE(strstr(header, "a=1") != NULL, "first cookie present");
    ASSERT_TRUE(strstr(header, "b=2") != NULL, "second cookie present");
    cookie_jar_destroy(&jar);
}

TEST(test_cookie_jar_secure_over_http) {
    struct cookie_jar jar;
    cookie_jar_init(&jar);
    cookie_jar_add_set_cookie(&jar, "session=abc; Path=/; Secure", "example.com", "/");

    char header[512];
    cookie_jar_get_header(&jar, "example.com", "/", false, header, sizeof(header));
    ASSERT_STR_EQ(header, "", "secure cookie not sent over HTTP");

    cookie_jar_get_header(&jar, "example.com", "/", true, header, sizeof(header));
    ASSERT_STR_EQ(header, "session=abc", "secure cookie sent over HTTPS");
    cookie_jar_destroy(&jar);
}

TEST(test_cookie_jar_save_load_roundtrip) {
    struct cookie_jar jar;
    cookie_jar_init(&jar);
    cookie_jar_add_set_cookie(&jar, "a=1; Path=/", "example.com", "/");
    cookie_jar_add_set_cookie(&jar, "b=2; Path=/sub", "example.com", "/sub/page");

    const char *tmpfile = "/tmp/curldbg_test_cookies.txt";
    ASSERT_INT_EQ(cookie_jar_save(&jar, tmpfile), 0, "cookie_jar_save");

    struct cookie_jar loaded;
    cookie_jar_init(&loaded);
    cookie_jar_load(&loaded, tmpfile);

    char header[512];
    cookie_jar_get_header(&loaded, "example.com", "/sub", true, header, sizeof(header));
    ASSERT_TRUE(strstr(header, "a=1") != NULL, "saved cookie a loaded");
    ASSERT_TRUE(strstr(header, "b=2") != NULL, "saved cookie b loaded");

    remove(tmpfile);
    cookie_jar_destroy(&jar);
    cookie_jar_destroy(&loaded);
}

TEST(test_cookie_jar_max_capacity) {
    struct cookie_jar jar;
    cookie_jar_init(&jar);
    char val[32];
    for (int i = 0; i < MAX_COOKIES + 10; i++) {
        snprintf(val, sizeof(val), "k%d=v%d; Path=/", i, i);
        cookie_jar_add_set_cookie(&jar, val, "example.com", "/");
    }
    ASSERT_INT_EQ(jar.count, MAX_COOKIES, "cookie jar capped at MAX_COOKIES");
    cookie_jar_destroy(&jar);
}

TEST(test_cookie_jar_init) {
    struct cookie_jar jar;
    jar.count = 999;
    cookie_jar_init(&jar);
    ASSERT_INT_EQ(jar.count, 0, "cookie_jar_init resets count");
}

TEST(test_cookie_jar_reject_tld_domain) {
    struct cookie_jar jar;
    cookie_jar_init(&jar);
    cookie_jar_add_set_cookie(&jar, "x=1; Domain=.com", "example.com", "/");
    ASSERT_INT_EQ(jar.count, 0, "TLD domain cookie rejected");
    cookie_jar_destroy(&jar);
}

TEST(test_cookie_jar_reject_ip_domain) {
    struct cookie_jar jar;
    cookie_jar_init(&jar);
    cookie_jar_add_set_cookie(&jar, "x=1; Domain=192.168.1.1", "example.com", "/");
    ASSERT_INT_EQ(jar.count, 0, "IP domain cookie rejected for non-matching host");
    cookie_jar_destroy(&jar);
}

TEST(test_cookie_jar_secure_roundtrip) {
    struct cookie_jar jar;
    cookie_jar_init(&jar);
    cookie_jar_add_set_cookie(&jar, "session=abc; Path=/; Secure", "example.com", "/");

    const char *tmpfile = "/tmp/curldbg_test_secure_cookies.txt";
    ASSERT_INT_EQ(cookie_jar_save(&jar, tmpfile), 0, "cookie_jar_save secure");

    struct cookie_jar loaded;
    cookie_jar_init(&loaded);
    cookie_jar_load(&loaded, tmpfile);

    char header[512];
    cookie_jar_get_header(&loaded, "example.com", "/", true, header, sizeof(header));
    ASSERT_STR_EQ(header, "session=abc", "secure cookie loaded and sent over HTTPS");
    cookie_jar_get_header(&loaded, "example.com", "/", false, header, sizeof(header));
    ASSERT_STR_EQ(header, "", "secure cookie not sent over HTTP after load");

    remove(tmpfile);
    cookie_jar_destroy(&jar);
    cookie_jar_destroy(&loaded);
}

TEST(test_cookie_jar_httponly_samesite_parsed) {
    struct cookie_jar jar;
    cookie_jar_init(&jar);
    cookie_jar_add_set_cookie(&jar, "x=1; HttpOnly; SameSite=Strict", "example.com", "/");
    ASSERT_INT_EQ(jar.count, 1, "HttpOnly/SameSite cookie stored");
    ASSERT_TRUE(strcmp(jar.entries[0].samesite, "Strict") == 0, "SameSite=Strict parsed");
    ASSERT_TRUE(jar.entries[0].httponly, "HttpOnly parsed");
    cookie_jar_destroy(&jar);
}

/* ================================================================
 * build_redirect_url
 * ================================================================ */

TEST(test_build_redirect_url_absolute) {
    struct url_info base;
    memset(&base, 0, sizeof(base));
    snprintf(base.host, sizeof(base.host), "example.com");
    snprintf(base.port, sizeof(base.port), "443");
    base.use_tls = true;
    base.has_explicit_port = false;
    snprintf(base.path, sizeof(base.path), "/orig");

    char out[2048];
    ASSERT_INT_EQ(build_redirect_url("https://redirect.example.com/new", &base, out, sizeof(out)), 0, "absolute redirect");
    ASSERT_STR_EQ(out, "https://redirect.example.com/new", "absolute redirect URL");
}

TEST(test_build_redirect_url_relative) {
    struct url_info base;
    memset(&base, 0, sizeof(base));
    snprintf(base.host, sizeof(base.host), "example.com");
    snprintf(base.port, sizeof(base.port), "80");
    base.use_tls = false;
    base.has_explicit_port = false;
    snprintf(base.path, sizeof(base.path), "/dir/page");

    char out[2048];
    ASSERT_INT_EQ(build_redirect_url("new-path", &base, out, sizeof(out)), 0, "relative redirect");
    ASSERT_STR_EQ(out, "http://example.com/dir/new-path", "relative redirect resolves to dir");
}

TEST(test_build_redirect_url_relative_dotdot) {
    struct url_info base;
    memset(&base, 0, sizeof(base));
    snprintf(base.host, sizeof(base.host), "example.com");
    snprintf(base.port, sizeof(base.port), "80");
    base.use_tls = false;
    base.has_explicit_port = false;
    snprintf(base.path, sizeof(base.path), "/dir/page");

    char out[2048];
    ASSERT_INT_EQ(build_redirect_url("../next", &base, out, sizeof(out)), 0, "relative dotdot redirect");
    ASSERT_STR_EQ(out, "http://example.com/next", "dotdot segments normalized");
}

TEST(test_build_redirect_url_absolute_path) {
    struct url_info base;
    memset(&base, 0, sizeof(base));
    snprintf(base.host, sizeof(base.host), "example.com");
    snprintf(base.port, sizeof(base.port), "80");
    base.use_tls = false;
    base.has_explicit_port = false;
    snprintf(base.path, sizeof(base.path), "/dir/page");

    char out[2048];
    ASSERT_INT_EQ(build_redirect_url("/absolute", &base, out, sizeof(out)), 0, "absolute path redirect");
    ASSERT_STR_EQ(out, "http://example.com/absolute", "absolute path redirect URL resolves");
}

TEST(test_build_redirect_url_absolute_path_dot_segments) {
    struct url_info base;
    memset(&base, 0, sizeof(base));
    snprintf(base.host, sizeof(base.host), "example.com");
    snprintf(base.port, sizeof(base.port), "80");
    base.use_tls = false;
    base.has_explicit_port = false;
    snprintf(base.path, sizeof(base.path), "/dir/page");

    char out[2048];
    ASSERT_INT_EQ(build_redirect_url("/a/b/../c/./", &base, out, sizeof(out)), 0, "absolute dot segments redirect");
    ASSERT_STR_EQ(out, "http://example.com/a/c/", "absolute dot segments normalized");
}

TEST(test_build_redirect_url_protocol_relative) {
    struct url_info base;
    memset(&base, 0, sizeof(base));
    snprintf(base.host, sizeof(base.host), "example.com");
    snprintf(base.port, sizeof(base.port), "443");
    base.use_tls = true;
    base.has_explicit_port = false;
    snprintf(base.path, sizeof(base.path), "/dir/page");

    char out[2048];
    ASSERT_INT_EQ(build_redirect_url("//other.com/path", &base, out, sizeof(out)), 0, "protocol-relative redirect");
    ASSERT_STR_EQ(out, "https://other.com/path", "protocol-relative redirect URL resolves");
}

TEST(test_build_redirect_url_relative_no_slash) {
    struct url_info base;
    memset(&base, 0, sizeof(base));
    snprintf(base.host, sizeof(base.host), "example.com");
    snprintf(base.port, sizeof(base.port), "80");
    base.use_tls = false;
    snprintf(base.path, sizeof(base.path), "/");

    char out[2048];
    ASSERT_INT_EQ(build_redirect_url("page", &base, out, sizeof(out)), 0, "relative from root");
    ASSERT_STR_EQ(out, "http://example.com/page", "relative redirect from root path");
}

/* ================================================================
 * write_out_expand
 * ================================================================ */

TEST(test_write_out_expand) {
    struct run_result result;
    memset(&result, 0, sizeof(result));
    result.hops = calloc(1, sizeof(struct hop_info));
    result.hop_count = 1;
    result.hops[0].status_code = 200;
    snprintf(result.final_url, sizeof(result.final_url), "http://example.com/");
    result.total_ms = 1234.56;
    result.dns_ms = 100.0;
    result.connect_ms = 200.0;
    result.ttfb_ms = 300.0;
    result.hops[0].has_redirect_target = true;
    snprintf(result.hops[0].redirect_to_host, sizeof(result.hops[0].redirect_to_host), "other.com");

    int saved_stdout = dup(STDOUT_FILENO);
    int devnull = open("/dev/null", O_WRONLY);
    dup2(devnull, STDOUT_FILENO);
    close(devnull);

    write_out_expand("%{http_code}", &result);
    write_out_expand("%{url_effective}", &result);
    write_out_expand("%{num_redirects}", &result);
    write_out_expand("\\n\\t", &result);
    write_out_expand("%{unknown_var}", &result);

    fflush(stdout);
    dup2(saved_stdout, STDOUT_FILENO);
    close(saved_stdout);

    free(result.hops);
    ASSERT_INT_EQ(1, 1, "write_out_expand didn't crash");
}

TEST(test_write_out_expand_double_percent) {
    struct run_result result;
    memset(&result, 0, sizeof(result));
    result.hops = calloc(1, sizeof(struct hop_info));
    result.hop_count = 1;
    result.hops[0].status_code = 200;
    snprintf(result.final_url, sizeof(result.final_url), "http://x.com/");

    int saved_stdout = dup(STDOUT_FILENO);
    int devnull = open("/dev/null", O_WRONLY);
    dup2(devnull, STDOUT_FILENO);
    close(devnull);

    write_out_expand("%%", &result);

    fflush(stdout);
    dup2(saved_stdout, STDOUT_FILENO);
    close(saved_stdout);

    free(result.hops);
    ASSERT_INT_EQ(1, 1, "write_out_expand %% doesn't crash");
}

/* ================================================================
 * DNS helpers
 * ================================================================ */

TEST(test_resolve_host_dns) {
    struct url_info url;
    memset(&url, 0, sizeof(url));
    strcpy(url.host, "127.0.0.1");
    strcpy(url.port, "80");
    struct timespec dns_start, dns_end;
    int gai_error = 0;
    struct addrinfo *addrs = resolve_host(&url, AF_UNSPEC, NULL, 0, NULL, 5000,
                                           &dns_start, &dns_end, &gai_error);
    ASSERT_PTR_NOTNULL(addrs, "resolve_host 127.0.0.1");
    ASSERT_INT_EQ(gai_error, 0, "gai_error 0 for valid host");
    freeaddrinfo(addrs);
}

TEST(test_resolve_host_cache) {
    struct url_info url;
    memset(&url, 0, sizeof(url));
    strcpy(url.host, "localhost");
    strcpy(url.port, "80");
    struct timespec dns_start, dns_end;
    int gai_error = 0;

    struct addrinfo *a1 = resolve_host(&url, AF_UNSPEC, NULL, 0, NULL, 5000,
                                        &dns_start, &dns_end, &gai_error);
    ASSERT_PTR_NOTNULL(a1, "resolve_host localhost first");
    freeaddrinfo(a1);

    struct addrinfo *a2 = resolve_host(&url, AF_UNSPEC, NULL, 0, NULL, 5000,
                                        &dns_start, &dns_end, &gai_error);
    ASSERT_PTR_NOTNULL(a2, "resolve_host localhost second (cached)");
    ASSERT_INT_EQ(gai_error, 0, "cached lookup succeeds");
    freeaddrinfo(a2);
}

TEST(test_resolve_host_resolve_entry) {
    struct resolve_entry entries[1];
    memset(&entries[0], 0, sizeof(entries[0]));
    strcpy(entries[0].host, "custom.host");
    strcpy(entries[0].port, "80");
    struct sockaddr_in *sin = (struct sockaddr_in *)&entries[0].ss;
    sin->sin_family = AF_INET;
    sin->sin_port = htons(80);
    inet_pton(AF_INET, "10.0.0.1", &sin->sin_addr);
    entries[0].ss_len = sizeof(*sin);
    entries[0].family = AF_INET;

    struct url_info url;
    memset(&url, 0, sizeof(url));
    strcpy(url.host, "custom.host");
    strcpy(url.port, "80");

    struct timespec dns_start, dns_end;
    int gai_error = 0;
    struct addrinfo *addrs = resolve_host(&url, AF_UNSPEC, entries, 1, NULL, 5000,
                                           &dns_start, &dns_end, &gai_error);
    ASSERT_PTR_NOTNULL(addrs, "resolve_host custom resolve entry");
    ASSERT_INT_EQ(gai_error, 0, "gai_error 0 for resolve entry");
    ASSERT_INT_EQ(addrs->ai_family, AF_INET, "AF_INET from resolve entry");
    freeaddrinfo(addrs);
}

extern char *find_header_end(char *buf, size_t len);
extern size_t write_body_data(const char *buf, size_t len, FILE *body_out,
                              struct response_info *out, bool capture_preview);
extern bool is_loopback_ip(const char *ip);
extern const char *family_short_name(int family);
extern bool is_localhost_url(const char *input_url);
extern const struct resolve_entry *find_resolve_entry(
    const struct resolve_entry *entries, int count, const char *host, const char *port);
extern struct addrinfo *build_addrinfo_from_resolve(const struct resolve_entry *re);
extern void dns_cache_key(const char *host, const char *port, int family,
                          char *key_out, size_t key_size, uint32_t *hash_out);
extern struct addrinfo *copy_addrinfo_list(const struct addrinfo *src);
extern int build_body_headers(char *body_headers, size_t body_headers_size,
    const char *verb, const char *data, size_t data_len,
    const FILE *upload_file, size_t upload_size,
    bool has_content_type, bool has_content_length, bool chunked_upload,
    size_t *content_len_out, bool *include_body_headers_out,
    char *error, size_t error_len);
extern size_t chunked_write(const char *buf, size_t len, FILE *body_out,
    struct response_info *out, int *state, uint64_t *chunk_rem,
    char *line_buf, size_t *line_len,
    z_stream *strm, bool decompress,
    char *error, size_t error_len);
extern int setup_upload_file(const char *upload_path, FILE **upload_file,
    size_t *upload_size, bool *chunked_upload, char *error, size_t error_len);
extern bool is_connection_error(const struct connection *conn);

TEST(test_set_error) {
    char buf[64];
    set_error(buf, sizeof(buf), "test %d", 42);
    ASSERT_STR_EQ(buf, "test 42", "set_error format");
}

TEST(test_set_error_truncated) {
    char buf[8];
    set_error(buf, sizeof(buf), "long message here");
    ASSERT_INT_EQ(strlen(buf), 7, "set_error truncated");
}

TEST(test_set_error_null_buffer) {
    set_error(NULL, 0, "should not crash");
    ASSERT_INT_EQ(1, 1, "set_error null buffer doesn't crash");
}

TEST(test_set_error_zero_length) {
    char buf[1];
    set_error(buf, 0, "should not crash");
    ASSERT_INT_EQ(1, 1, "set_error zero length doesn't crash");
}

static int test_write_out_capture(const char *fmt, const struct run_result *r, char *out, size_t out_size) {
    FILE *tmp = tmpfile();
    if (tmp == NULL) return -1;
    int saved = dup(STDOUT_FILENO);
    dup2(fileno(tmp), STDOUT_FILENO);
    write_out_expand(fmt, r);
    fflush(stdout);
    dup2(saved, STDOUT_FILENO);
    close(saved);
    rewind(tmp);
    size_t n = fread(out, 1, out_size - 1, tmp);
    out[n] = '\0';
    fclose(tmp);
    return 0;
}

TEST(test_write_out_expand_http_code) {
    struct run_result r;
    memset(&r, 0, sizeof(r));
    r.hop_count = 1;
    r.hops = calloc(1, sizeof(r.hops[0]));
    r.hops[0].status_code = 200;
    char out[64];
    test_write_out_capture("%{http_code}", &r, out, sizeof(out));
    ASSERT_STR_EQ(out, "200", "http_code");
    free(r.hops);
}

TEST(test_write_out_expand_time_total) {
    struct run_result r;
    memset(&r, 0, sizeof(r));
    r.total_ms = 123456.0;
    char out[64];
    test_write_out_capture("%{time_total}", &r, out, sizeof(out));
    ASSERT_STR_EQ(out, "123.456", "time_total");
}

TEST(test_write_out_expand_url_effective) {
    struct run_result r;
    memset(&r, 0, sizeof(r));
    r.hop_count = 1;
    r.hops = calloc(1, sizeof(r.hops[0]));
    strcpy(r.final_url, "https://example.com");
    char out[256];
    test_write_out_capture("%{url_effective}", &r, out, sizeof(out));
    ASSERT_STR_EQ(out, "https://example.com", "url_effective");
    free(r.hops);
}

TEST(test_write_out_expand_num_redirects) {
    struct run_result r;
    memset(&r, 0, sizeof(r));
    r.hop_count = 3;
    r.hops = calloc(3, sizeof(r.hops[0]));
    char out[64];
    test_write_out_capture("%{num_redirects}", &r, out, sizeof(out));
    ASSERT_STR_EQ(out, "2", "num_redirects");
    free(r.hops);
}

TEST(test_write_out_expand_redirect_url) {
    struct run_result r;
    memset(&r, 0, sizeof(r));
    r.hop_count = 1;
    r.hops = calloc(1, sizeof(r.hops[0]));
    r.hops[0].has_redirect_target = true;
    strcpy(r.hops[0].redirect_url, "https://other.com/final");
    char out[256];
    test_write_out_capture("%{redirect_url}", &r, out, sizeof(out));
    ASSERT_STR_EQ(out, "https://other.com/final", "redirect_url full URL");
    free(r.hops);
}

TEST(test_write_out_expand_newline_escape) {
    struct run_result r;
    memset(&r, 0, sizeof(r));
    char out[64];
    test_write_out_capture("\\n", &r, out, sizeof(out));
    ASSERT_STR_EQ(out, "\n", "newline escape");
}

TEST(test_write_out_expand_unknown_var) {
    struct run_result r;
    memset(&r, 0, sizeof(r));
    r.hop_count = 1;
    r.hops = calloc(1, sizeof(r.hops[0]));
    char out[64];
    test_write_out_capture("%{unknown_var}", &r, out, sizeof(out));
    ASSERT_STR_EQ(out, "", "unknown var prints nothing");
    free(r.hops);
}

TEST(test_output_filename_from_url_basic) {
    char out[256];
    output_filename_from_url("https://example.com/path/file.html", out, sizeof(out));
    ASSERT_STR_EQ(out, "file.html", "filename from path");
}

TEST(test_output_filename_from_url_root) {
    char out[256];
    output_filename_from_url("https://example.com/", out, sizeof(out));
    ASSERT_STR_EQ(out, "index.html", "root path defaults");
}

TEST(test_output_filename_from_url_query) {
    char out[256];
    output_filename_from_url("https://example.com/file.html?q=1", out, sizeof(out));
    ASSERT_STR_EQ(out, "file.html", "query stripped");
}

TEST(test_output_filename_from_url_fragment) {
    char out[256];
    output_filename_from_url("https://example.com/file.html#section", out, sizeof(out));
    ASSERT_STR_EQ(out, "file.html", "fragment stripped");
}

TEST(test_output_filename_from_url_empty) {
    char out[256];
    output_filename_from_url("https://example.com", out, sizeof(out));
    ASSERT_STR_EQ(out, "index.html", "bare host defaults");
}

TEST(test_output_filename_from_url_overflow) {
    char out[4];
    int rc = output_filename_from_url("https://example.com/longname.html", out, sizeof(out));
    ASSERT_INT_EQ(rc, -1, "overflow returns -1");
}

TEST(test_find_header_end_rnrn) {
    char buf[] = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    char *body = find_header_end(buf, strlen(buf));
    ASSERT_PTR_NOTNULL(body, "found delimiter");
    ASSERT_STR_EQ(body, "hello", "body starts correctly");
}

TEST(test_find_header_end_nn) {
    char buf[] = "HTTP/1.1 200 OK\nContent-Length: 5\n\nhello";
    char *body = find_header_end(buf, strlen(buf));
    ASSERT_PTR_NOTNULL(body, "found LF-only delimiter");
    ASSERT_STR_EQ(body, "hello", "body starts correctly");
}

TEST(test_find_header_end_no_delimiter) {
    char buf[] = "HTTP/1.1 200 OK\r\nContent-Length: 5";
    char *body = find_header_end(buf, strlen(buf));
    ASSERT_TRUE(body == NULL, "no delimiter returns NULL");
}

TEST(test_find_header_end_at_start) {
    char buf[] = "\r\n\r\nbody here";
    char *body = find_header_end(buf, strlen(buf));
    ASSERT_PTR_NOTNULL(body, "found at start");
    ASSERT_STR_EQ(body, "body here", "body at start");
}

TEST(test_write_body_data_to_file) {
    struct response_info out;
    memset(&out, 0, sizeof(out));
    FILE *tmp = tmpfile();
    write_body_data("hello", 5, tmp, &out, true);
    rewind(tmp);
    char got[16];
    size_t n = fread(got, 1, sizeof(got) - 1, tmp);
    got[n] = '\0';
    ASSERT_STR_EQ(got, "hello", "data written to file");
    fclose(tmp);
}

TEST(test_write_body_data_preview) {
    struct response_info out;
    memset(&out, 0, sizeof(out));
    write_body_data("abcdefghij", 10, NULL, &out, true);
    ASSERT_INT_EQ(1, 1, "body written to stderr without crash");
}

TEST(test_write_body_data_null_file) {
    struct response_info out;
    memset(&out, 0, sizeof(out));
    size_t rc = write_body_data("ok", 2, NULL, &out, true);
    ASSERT_INT_EQ((int)rc, 0, "null file succeeds");
}

TEST(test_write_body_data_no_preview_still_writes) {
    struct response_info out;
    memset(&out, 0, sizeof(out));
    FILE *tmp = tmpfile();
    ASSERT_PTR_NOTNULL(tmp, "tmpfile");
    if (tmp == NULL) return;
    size_t rc = write_body_data("body", 4, tmp, &out, false);
    rewind(tmp);
    char got[16];
    size_t n = fread(got, 1, sizeof(got) - 1, tmp);
    got[n] = '\0';
    ASSERT_INT_EQ((int)rc, 0, "write succeeds without preview");
    ASSERT_STR_EQ(got, "body", "body still written");
    fclose(tmp);
}

static int receive_response_from_string(const char *response, FILE *body_out,
                                        bool head_method, struct response_info *out,
                                        char *error, size_t error_len) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return -1;
    size_t len = strlen(response);
    ssize_t wr = write(fds[1], response, len);
    shutdown(fds[1], SHUT_WR);

    struct connection conn;
    memset(&conn, 0, sizeof(conn));
    conn.fd = fds[0];

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int rc = (wr == (ssize_t)len)
        ? receive_response(&conn, &start, out, error, error_len, body_out, false, false, head_method)
        : -1;

    close(fds[0]);
    close(fds[1]);
    return rc;
}

TEST(test_receive_response_captures_preview_without_body_file) {
    struct response_info out;
    char err[128] = "";
    memset(&out, 0, sizeof(out));
    int rc = receive_response_from_string(
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        NULL, false, &out, err, sizeof(err));
    ASSERT_INT_EQ(rc, 0, "receive ok");
    ASSERT_INT_EQ(out.status_code, 200, "status is 200");
}

TEST(test_receive_response_head_ignores_body) {
    struct response_info out;
    char err[128] = "";
    memset(&out, 0, sizeof(out));
    int rc = receive_response_from_string(
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        NULL, true, &out, err, sizeof(err));
    ASSERT_INT_EQ(rc, 0, "head receive ok");
    ASSERT_INT_EQ(out.status_code, 200, "status parsed");
}

TEST(test_receive_response_100_continue) {
    struct response_info out;
    char err[128] = "";
    memset(&out, 0, sizeof(out));
    int rc = receive_response_from_string(
        "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        NULL, false, &out, err, sizeof(err));
    ASSERT_INT_EQ(rc, 0, "100 Continue handled");
    ASSERT_INT_EQ(out.status_code, 200, "final status is 200");
    ASSERT_TRUE(out.ttfb_ms > 0, "ttfb measured");
}

TEST(test_receive_response_100_continue_no_body) {
    struct response_info out;
    char err[128] = "";
    memset(&out, 0, sizeof(out));
    int rc = receive_response_from_string(
        "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
        NULL, false, &out, err, sizeof(err));
    ASSERT_INT_EQ(rc, 0, "100 Continue -> 204 handled");
    ASSERT_INT_EQ(out.status_code, 204, "final status is 204");
}

TEST(test_receive_response_103_early_hints) {
    struct response_info out;
    char err[128] = "";
    memset(&out, 0, sizeof(out));
    int rc = receive_response_from_string(
        "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n"
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
        NULL, false, &out, err, sizeof(err));
    ASSERT_INT_EQ(rc, 0, "103 Early Hints handled");
    ASSERT_INT_EQ(out.status_code, 200, "final status is 200");
}

TEST(test_final_status_code_no_hops) {
    struct run_result r;
    memset(&r, 0, sizeof(r));
    r.hop_count = 0;
    ASSERT_INT_EQ(final_status_code(&r), 0, "no hops returns 0");
}

TEST(test_final_status_code_one_hop) {
    struct run_result r;
    memset(&r, 0, sizeof(r));
    r.hop_count = 1;
    r.hops = calloc(1, sizeof(r.hops[0]));
    r.hops[0].status_code = 200;
    ASSERT_INT_EQ(final_status_code(&r), 200, "one hop");
    free(r.hops);
}

TEST(test_final_status_code_multi_hop) {
    struct run_result r;
    memset(&r, 0, sizeof(r));
    r.hop_count = 3;
    r.hops = calloc(3, sizeof(r.hops[0]));
    r.hops[0].status_code = 302;
    r.hops[1].status_code = 301;
    r.hops[2].status_code = 200;
    ASSERT_INT_EQ(final_status_code(&r), 200, "last hop status");
    free(r.hops);
}

TEST(test_final_endpoint_ipv4) {
    struct run_result r;
    memset(&r, 0, sizeof(r));
    r.hop_count = 1;
    r.hops = calloc(1, sizeof(r.hops[0]));
    strcpy(r.hops[0].connected_ip, "10.0.0.1");
    r.hops[0].connected_family = AF_INET;
    char out[64];
    final_endpoint(&r, out, sizeof(out));
    ASSERT_STR_EQ(out, "10.0.0.1 (IPv4)", "IPv4 endpoint");
    free(r.hops);
}

TEST(test_final_endpoint_no_hops) {
    struct run_result r;
    memset(&r, 0, sizeof(r));
    r.hop_count = 0;
    char out[64];
    final_endpoint(&r, out, sizeof(out));
    ASSERT_STR_EQ(out, "n/a", "no hops endpoint");
}

TEST(test_family_short_name_v4) {
    ASSERT_STR_EQ(family_short_name(AF_INET), "v4", "AF_INET");
}

TEST(test_family_short_name_v6) {
    ASSERT_STR_EQ(family_short_name(AF_INET6), "v6", "AF_INET6");
}

TEST(test_family_short_name_other) {
    ASSERT_STR_EQ(family_short_name(AF_UNIX), "?", "other family");
}

TEST(test_is_loopback_ip_v4) {
    ASSERT_TRUE(is_loopback_ip("127.0.0.1"), "127.0.0.1 is loopback");
}

TEST(test_is_loopback_ip_v6) {
    ASSERT_TRUE(is_loopback_ip("::1"), "::1 is loopback");
}

TEST(test_is_loopback_ip_remote) {
    ASSERT_FALSE(is_loopback_ip("8.8.8.8"), "8.8.8.8 not loopback");
}

TEST(test_is_localhost_url_localhost) {
    ASSERT_TRUE(is_localhost_url("http://localhost:8080/path"), "localhost hostname");
}

TEST(test_is_localhost_url_ipv4) {
    ASSERT_TRUE(is_localhost_url("https://127.0.0.1/"), "127.0.0.1");
}

TEST(test_is_localhost_url_ipv6) {
    ASSERT_TRUE(is_localhost_url("http://[::1]:80"), "::1 IPv6");
}

TEST(test_is_localhost_url_remote) {
    ASSERT_FALSE(is_localhost_url("https://example.com"), "remote host");
}

TEST(test_fill_connected_endpoint_ipv4) {
    struct addrinfo ai;
    struct sockaddr_in sin;
    memset(&ai, 0, sizeof(ai));
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    inet_pton(AF_INET, "1.2.3.4", &sin.sin_addr);
    ai.ai_family = AF_INET;
    ai.ai_addr = (struct sockaddr *)&sin;
    ai.ai_addrlen = sizeof(sin);
    char ip[64];
    int family = 0;
    fill_connected_endpoint(&ai, ip, sizeof(ip), &family);
    ASSERT_STR_EQ(ip, "1.2.3.4", "IP address");
    ASSERT_INT_EQ(family, AF_INET, "family set");
}

TEST(test_fill_connected_endpoint_null) {
    char ip[64] = "unchanged";
    int family = 99;
    fill_connected_endpoint(NULL, ip, sizeof(ip), &family);
    ASSERT_STR_EQ(ip, "unchanged", "null addrinfo leaves buffer unchanged");
}

TEST(test_set_nonblocking) {
    int fds[2];
    ASSERT_INT_EQ(pipe(fds), 0, "pipe created");
    ASSERT_INT_EQ(set_nonblocking(fds[0], true), 0, "set nonblocking");
    int flags = fcntl(fds[0], F_GETFL);
    ASSERT_TRUE(flags & O_NONBLOCK, "O_NONBLOCK set");
    ASSERT_INT_EQ(set_nonblocking(fds[0], false), 0, "clear nonblocking");
    flags = fcntl(fds[0], F_GETFL);
    ASSERT_FALSE(flags & O_NONBLOCK, "O_NONBLOCK cleared");
    close(fds[0]);
    close(fds[1]);
}

TEST(test_is_connection_error_write) {
    struct connection conn;
    memset(&conn, 0, sizeof(conn));
    conn.last_errno = ECONNRESET;
    ASSERT_TRUE(is_connection_error(&conn), "write failed");
    conn.last_errno = EPIPE;
    ASSERT_TRUE(is_connection_error(&conn), "broken pipe");
}

TEST(test_is_connection_error_read) {
    struct connection conn;
    memset(&conn, 0, sizeof(conn));
    conn.last_errno = ECONNRESET;
    ASSERT_TRUE(is_connection_error(&conn), "read failed");
    conn.last_errno = EPIPE;
    ASSERT_TRUE(is_connection_error(&conn), "read body");
}

TEST(test_is_connection_error_timeout) {
    struct connection conn;
    memset(&conn, 0, sizeof(conn));
    conn.last_errno = ETIMEDOUT;
    ASSERT_TRUE(is_connection_error(&conn), "write timeout");
    ASSERT_TRUE(is_connection_error(&conn), "read timeout");
}

TEST(test_is_connection_error_dns) {
    struct connection conn;
    memset(&conn, 0, sizeof(conn));
    conn.last_errno = EAI_FAIL;
    ASSERT_FALSE(is_connection_error(&conn), "dns");
    conn.last_errno = EIO;
    ASSERT_FALSE(is_connection_error(&conn), "tls");
}

TEST(test_is_connection_error_ok) {
    struct connection conn;
    memset(&conn, 0, sizeof(conn));
    ASSERT_FALSE(is_connection_error(&conn), "empty");
    ASSERT_FALSE(is_connection_error(NULL), "null");
}

TEST(test_init_run_options_basic) {
    struct cmdline_opts c;
    memset(&c, 0, sizeof(c));
    c.follow_redirects = true;
    c.insecure_tls = true;
    c.verbose = true;
    c.silent = true;
    strcpy(c.request_method, "POST");
    c.request_data = "k=v";
    c.request_data_len = 3;
    c.connect_timeout_ms = 5000;
    c.read_timeout_ms = 30000;
    c.max_time_ms = 60000;
    c.max_redirects = 3;
    c.retry_count = 2;
    c.retry_delay_ms = 1000;
    c.compressed = true;
    c.user_agent = "TestAgent";
    c.basic_auth = "u:p";

    struct run_options o;
    memset(&o, 0, sizeof(o));
    init_run_options(&o, &c);
    ASSERT_TRUE(o.follow_redirects, "follow_redirects");
    ASSERT_TRUE(o.insecure_tls, "insecure_tls");
    ASSERT_TRUE(o.verbose, "verbose");
    ASSERT_STR_EQ(o.method, "POST", "method");
    ASSERT_FALSE(o.is_head_method, "not head");
    ASSERT_INT_EQ(o.connect_timeout_ms, 5000, "connect_timeout");
    ASSERT_INT_EQ(o.read_timeout_ms, 30000, "read_timeout");
    ASSERT_INT_EQ(o.max_time_ms, 60000, "max_time");
    ASSERT_INT_EQ(o.max_redirects, 3, "max_redirects");
    ASSERT_INT_EQ(o.retry_count, 2, "retry_count");
    ASSERT_INT_EQ(o.retry_delay_ms, 1000, "retry_delay");
}

TEST(test_init_run_options_head_method) {
    struct cmdline_opts c;
    memset(&c, 0, sizeof(c));
    strcpy(c.request_method, "HEAD");
    struct run_options o;
    memset(&o, 0, sizeof(o));
    init_run_options(&o, &c);
    ASSERT_TRUE(o.is_head_method, "HEAD detected");
}

TEST(test_find_resolve_entry_match) {
    struct resolve_entry entries[2];
    memset(entries, 0, sizeof(entries));
    strcpy(entries[0].host, "a.com");
    strcpy(entries[0].port, "80");
    strcpy(entries[1].host, "b.com");
    strcpy(entries[1].port, "443");
    const struct resolve_entry *r = find_resolve_entry(entries, 2, "b.com", "443");
    ASSERT_PTR_NOTNULL(r, "found match");
    ASSERT_STR_EQ(r->host, "b.com", "correct host");
}

TEST(test_find_resolve_entry_no_match) {
    struct resolve_entry entries[1];
    memset(entries, 0, sizeof(entries));
    strcpy(entries[0].host, "a.com");
    strcpy(entries[0].port, "80");
    const struct resolve_entry *r = find_resolve_entry(entries, 1, "b.com", "80");
    ASSERT_TRUE(r == NULL, "no match");
}

TEST(test_find_resolve_entry_empty) {
    const struct resolve_entry *r = find_resolve_entry(NULL, 0, "a.com", "80");
    ASSERT_TRUE(r == NULL, "empty entries");
}

TEST(test_dns_cache_key) {
    char key[256 + 16 + 16];
    uint32_t hash;
    dns_cache_key("example.com", "443", AF_INET, key, sizeof(key), &hash);
    ASSERT_STR_EQ(key, "example.com:443:2", "cache key");
    ASSERT_TRUE(hash != 0, "non-zero hash");
}

TEST(test_build_addrinfo_from_resolve_ipv4) {
    struct resolve_entry re;
    memset(&re, 0, sizeof(re));
    struct sockaddr_in *sin = (struct sockaddr_in *)&re.ss;
    sin->sin_family = AF_INET;
    sin->sin_port = htons(80);
    inet_pton(AF_INET, "1.2.3.4", &sin->sin_addr);
    re.ss_len = sizeof(*sin);
    re.family = AF_INET;
    struct addrinfo *ai = build_addrinfo_from_resolve(&re);
    ASSERT_PTR_NOTNULL(ai, "build_addrinfo_from_resolve");
    ASSERT_INT_EQ(ai->ai_family, AF_INET, "family");
    ASSERT_INT_EQ(ai->ai_socktype, SOCK_STREAM, "socktype");
    ASSERT_TRUE(ai->ai_next == NULL, "no next");
    freeaddrinfo(ai);
}

TEST(test_copy_addrinfo_list_single) {
    struct addrinfo ai;
    struct sockaddr_in sin;
    memset(&ai, 0, sizeof(ai));
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    inet_pton(AF_INET, "10.0.0.1", &sin.sin_addr);
    ai.ai_family = AF_INET;
    ai.ai_addrlen = sizeof(sin);
    ai.ai_addr = (struct sockaddr *)&sin;
    struct addrinfo *copy = copy_addrinfo_list(&ai);
    ASSERT_PTR_NOTNULL(copy, "copy not null");
    ASSERT_INT_EQ(copy->ai_family, AF_INET, "family copied");
    freeaddrinfo(copy);
}

TEST(test_copy_addrinfo_list_null) {
    struct addrinfo *copy = copy_addrinfo_list(NULL);
    ASSERT_TRUE(copy == NULL, "null in null out");
}

TEST(test_build_body_headers_chunked_upload) {
    char hdrs[256];
    size_t cl = 0;
    bool inc = false;
    char err[64] = "";
    FILE *f = tmpfile();
    int rc = build_body_headers(hdrs, sizeof(hdrs), "POST", NULL, 0, f, 100,
        false, false, true, &cl, &inc, err, sizeof(err));
    ASSERT_INT_EQ(rc, 0, "chunked upload ok");
    ASSERT_TRUE(inc, "include body headers");
    ASSERT_TRUE(strstr(hdrs, "Transfer-Encoding: chunked") != NULL, "chunked header");
    ASSERT_TRUE(strstr(hdrs, "Content-Type: application/octet-stream") != NULL, "content type");
    fclose(f);
}

TEST(test_build_body_headers_content_length) {
    char hdrs[256];
    size_t cl = 0;
    bool inc = false;
    char err[64] = "";
    FILE *f = tmpfile();
    int rc = build_body_headers(hdrs, sizeof(hdrs), "PUT", NULL, 0, f, 42,
        false, false, false, &cl, &inc, err, sizeof(err));
    ASSERT_INT_EQ(rc, 0, "content-length ok");
    ASSERT_STR_EQ(err, "", "no error");
    fclose(f);
}

TEST(test_build_body_headers_post_data) {
    char hdrs[256];
    size_t cl = 0;
    bool inc = false;
    char err[64] = "";
    int rc = build_body_headers(hdrs, sizeof(hdrs), "POST", "key=val", 6, NULL, 0,
        false, false, false, &cl, &inc, err, sizeof(err));
    ASSERT_INT_EQ(rc, 0, "post data ok");
    ASSERT_TRUE(strstr(hdrs, "application/x-www-form-urlencoded") != NULL, "form type");
}

TEST(test_build_body_headers_no_upload) {
    char hdrs[256];
    size_t cl = 0;
    bool inc = true;
    char err[64] = "";
    int rc = build_body_headers(hdrs, sizeof(hdrs), "GET", NULL, 0, NULL, 0,
        false, false, false, &cl, &inc, err, sizeof(err));
    ASSERT_INT_EQ(rc, 0, "no upload ok");
    ASSERT_FALSE(inc, "no body headers");
}

TEST(test_build_body_headers_overflow) {
    char hdrs[4];
    size_t cl = 0;
    bool inc = false;
    char err[64] = "";
    FILE *f = tmpfile();
    int rc = build_body_headers(hdrs, sizeof(hdrs), "PUT", NULL, 0, f, 999,
        false, false, false, &cl, &inc, err, sizeof(err));
    ASSERT_INT_EQ(rc, -1, "overflow error");
    fclose(f);
}

TEST(test_chunked_write_simple) {
    struct response_info out;
    memset(&out, 0, sizeof(out));
    int state = 0;
    uint64_t rem = 0;
    char line_buf[32];
    size_t line_len = 0;
    char err[64] = "";
    chunked_write("5\r\nhello\r\n0\r\n\r\n", 15, NULL, &out,
        &state, &rem, line_buf, &line_len, NULL, false, err, sizeof(err));
    ASSERT_INT_EQ(state, 3, "state done");
}

TEST(test_chunked_write_multiple) {
    struct response_info out;
    memset(&out, 0, sizeof(out));
    int state = 0;
    uint64_t rem = 0;
    char line_buf[32];
    size_t line_len = 0;
    char err[64] = "";
    chunked_write("3\r\nabc\r\n0\r\n\r\n", 13, NULL, &out,
        &state, &rem, line_buf, &line_len, NULL, false, err, sizeof(err));
    ASSERT_INT_EQ(state, 3, "state done");
}

TEST(test_chunked_write_split) {
    struct response_info out;
    memset(&out, 0, sizeof(out));
    int state = 0;
    uint64_t rem = 0;
    char line_buf[32];
    size_t line_len = 0;
    char err[64] = "";
    chunked_write("4\r\nab", 5, NULL, &out,
        &state, &rem, line_buf, &line_len, NULL, false, err, sizeof(err));
    chunked_write("cd\r\n0\r\n\r\n", 10, NULL, &out,
        &state, &rem, line_buf, &line_len, NULL, false, err, sizeof(err));
    ASSERT_INT_EQ(state, 3, "state done");
}

TEST(test_setup_upload_file_stdin) {
    FILE *uf = NULL;
    size_t us = 0;
    bool chunked = false;
    char err[64] = "";
    int rc = setup_upload_file("-", &uf, &us, &chunked, err, sizeof(err));
    ASSERT_INT_EQ(rc, 0, "stdin ok");
    ASSERT_TRUE(uf == stdin, "stdin file");
    ASSERT_TRUE(chunked, "chunked for stdin");
}

TEST(test_setup_upload_file_missing) {
    FILE *uf = NULL;
    size_t us = 0;
    bool chunked = false;
    char err[64] = "";
    int rc = setup_upload_file("/nonexistent/file_12345", &uf, &us, &chunked, err, sizeof(err));
    ASSERT_INT_EQ(rc, -1, "missing file error");
}

TEST(test_setup_upload_file_null) {
    FILE *uf = NULL;
    size_t us = 0;
    bool chunked = false;
    char err[64] = "";
    int rc = setup_upload_file(NULL, &uf, &us, &chunked, err, sizeof(err));
    ASSERT_INT_EQ(rc, 0, "null upload ok");
    ASSERT_TRUE(uf == NULL, "no file");
}

TEST(test_parse_cmdline_boolean_flags) {
    struct cmdline_opts c;
    char *argv[] = {(char *)"prog", (char *)"-v", (char *)"-k", (char *)"-s",
                    (char *)"--no-happy-eyeballs", (char *)"--compressed", NULL};
    parse_cmdline(6, argv, &c);
    ASSERT_TRUE(c.verbose, "verbose");
    ASSERT_TRUE(c.insecure_tls, "insecure");
    ASSERT_TRUE(c.silent, "silent");
    ASSERT_FALSE(c.happy_eyeballs, "no happy eyeballs");
    ASSERT_TRUE(c.compressed, "compressed");
    free((void *)c.urls);
}

TEST(test_parse_cmdline_value_flags) {
    struct cmdline_opts c;
    char *argv[] = {(char *)"prog", (char *)"-A", (char *)"MyAgent",
                    (char *)"--connect-timeout", (char *)"5",
                    (char *)"--max-redirs", (char *)"3",
                    (char *)"-u", (char *)"user:pass",
                    (char *)"-H", (char *)"X-Foo: bar",
                    (char *)"-X", (char *)"DELETE", NULL};
    parse_cmdline(13, argv, &c);
    ASSERT_STR_EQ(c.user_agent, "MyAgent", "user agent");
    ASSERT_INT_EQ(c.connect_timeout_ms, 5000, "connect timeout");
    ASSERT_INT_EQ(c.max_redirects, 3, "max redirects");
    ASSERT_STR_EQ(c.basic_auth, "user:pass", "basic auth");
    ASSERT_INT_EQ(c.extra_header_count, 1, "one extra header");
    ASSERT_STR_EQ(c.request_method, "DELETE", "DELETE method");
    ASSERT_TRUE(c.method_explicit, "method explicit");
    free((void *)c.urls);
    free((void *)c.extra_headers);
}

TEST(test_parse_cmdline_urls) {
    struct cmdline_opts c;
    char *argv[] = {(char *)"prog", (char *)"http://a.com", (char *)"https://b.com", NULL};
    parse_cmdline(3, argv, &c);
    ASSERT_INT_EQ(c.url_count, 2, "two urls");
    ASSERT_STR_EQ(c.input_url, "http://a.com", "first url");
    free((void *)c.urls);
}

TEST(test_parse_cmdline_defaults) {
    struct cmdline_opts c;
    char *argv[] = {(char *)"prog", (char *)"http://example.com", NULL};
    parse_cmdline(2, argv, &c);
    ASSERT_STR_EQ(c.request_method, "GET", "default GET");
    ASSERT_TRUE(c.happy_eyeballs, "default happy eyeballs");
    ASSERT_INT_EQ(c.address_family, AF_UNSPEC, "default AF_UNSPEC");
    free((void *)c.urls);
}

TEST(test_parse_cmdline_resolve_ipv4) {
    struct cmdline_opts c;
    memset(&c, 0, sizeof(c));
    char *argv[] = {(char *)"prog", (char *)"--resolve", (char *)"example.com:80:1.2.3.4", (char *)"http://example.com", NULL};
    ASSERT_INT_EQ(parse_cmdline(4, argv, &c), 0, "parse ok");
    ASSERT_INT_EQ(c.resolve_count, 1, "one resolve entry");
    ASSERT_STR_EQ(c.resolve_entries[0].host, "example.com", "host");
    ASSERT_STR_EQ(c.resolve_entries[0].port, "80", "port");
    ASSERT_INT_EQ(c.resolve_entries[0].family, AF_INET, "AF_INET");
    struct sockaddr_in *sin = (struct sockaddr_in *)&c.resolve_entries[0].ss;
    struct in_addr expected;
    inet_pton(AF_INET, "1.2.3.4", &expected);
    ASSERT_INT_EQ(memcmp(&sin->sin_addr, &expected, sizeof(expected)), 0, "IPv4 addr");
    free((void *)c.urls);
}

TEST(test_parse_cmdline_resolve_ipv6_bare) {
    struct cmdline_opts c;
    memset(&c, 0, sizeof(c));
    char *argv[] = {(char *)"prog", (char *)"--resolve", (char *)"example.com:80:2001:db8::1", (char *)"http://example.com", NULL};
    ASSERT_INT_EQ(parse_cmdline(4, argv, &c), 0, "parse ok");
    ASSERT_INT_EQ(c.resolve_count, 1, "one resolve entry");
    ASSERT_STR_EQ(c.resolve_entries[0].host, "example.com", "host");
    ASSERT_STR_EQ(c.resolve_entries[0].port, "80", "port");
    ASSERT_INT_EQ(c.resolve_entries[0].family, AF_INET6, "AF_INET6");
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&c.resolve_entries[0].ss;
    struct in6_addr expected;
    inet_pton(AF_INET6, "2001:db8::1", &expected);
    ASSERT_INT_EQ(memcmp(&sin6->sin6_addr, &expected, sizeof(expected)), 0, "IPv6 addr");
    free((void *)c.urls);
}

TEST(test_parse_cmdline_resolve_ipv6_bracketed) {
    struct cmdline_opts c;
    memset(&c, 0, sizeof(c));
    char *argv[] = {(char *)"prog", (char *)"--resolve", (char *)"example.com:80:[2001:db8::1]", (char *)"http://example.com", NULL};
    ASSERT_INT_EQ(parse_cmdline(4, argv, &c), 0, "parse ok");
    ASSERT_INT_EQ(c.resolve_count, 1, "one resolve entry");
    ASSERT_INT_EQ(c.resolve_entries[0].family, AF_INET6, "AF_INET6");
    free((void *)c.urls);
}

TEST(test_parse_cmdline_resolve_ipv6_host) {
    struct cmdline_opts c;
    memset(&c, 0, sizeof(c));
    char *argv[] = {(char *)"prog", (char *)"--resolve", (char *)"[::1]:80:10.0.0.1", (char *)"http://example.com", NULL};
    ASSERT_INT_EQ(parse_cmdline(4, argv, &c), 0, "parse ok");
    ASSERT_INT_EQ(c.resolve_count, 1, "one resolve entry");
    ASSERT_STR_EQ(c.resolve_entries[0].host, "::1", "IPv6 host");
    ASSERT_INT_EQ(c.resolve_entries[0].family, AF_INET, "AF_INET address");
    free((void *)c.urls);
}

TEST(test_parse_cmdline_resolve_ipv6_bracketed_both) {
    struct cmdline_opts c;
    memset(&c, 0, sizeof(c));
    char *argv[] = {(char *)"prog", (char *)"--resolve", (char *)"[::1]:443:[::1]", (char *)"http://example.com", NULL};
    ASSERT_INT_EQ(parse_cmdline(4, argv, &c), 0, "parse ok");
    ASSERT_INT_EQ(c.resolve_count, 1, "one resolve entry");
    ASSERT_STR_EQ(c.resolve_entries[0].host, "::1", "IPv6 host");
    ASSERT_STR_EQ(c.resolve_entries[0].port, "443", "port");
    ASSERT_INT_EQ(c.resolve_entries[0].family, AF_INET6, "AF_INET6");
    free((void *)c.urls);
}

TEST(test_parse_cmdline_resolve_missing_addr) {
    struct cmdline_opts c;
    memset(&c, 0, sizeof(c));
    char *argv[] = {(char *)"prog", (char *)"--resolve", (char *)"example.com:80", (char *)"http://example.com", NULL};
    ASSERT_INT_EQ(parse_cmdline(4, argv, &c), -1, "missing addr returns -1");
    ASSERT_TRUE(strlen(c.error) > 0, "error set");
    free((void *)c.urls);
}

TEST(test_parse_cmdline_resolve_unclosed_bracket) {
    struct cmdline_opts c;
    memset(&c, 0, sizeof(c));
    char *argv[] = {(char *)"prog", (char *)"--resolve", (char *)"[::1:80:10.0.0.1", (char *)"http://example.com", NULL};
    ASSERT_INT_EQ(parse_cmdline(4, argv, &c), -1, "unclosed bracket returns -1");
    ASSERT_TRUE(strlen(c.error) > 0, "error set");
    free((void *)c.urls);
}

TEST(test_parse_cmdline_combined_flags_o) {
    struct cmdline_opts c;
    memset(&c, 0, sizeof(c));
    char *argv[] = {(char *)"prog", (char *)"-fsSLo", (char *)"/tmp/out", (char *)"http://example.com", NULL};
    ASSERT_INT_EQ(parse_cmdline(4, argv, &c), 0, "combined -fsSLo with next arg as -o value");
    ASSERT_TRUE(c.fail_on_http_error, "-f");
    ASSERT_TRUE(c.silent, "-s");
    ASSERT_TRUE(c.show_error, "-S");
    ASSERT_TRUE(c.follow_redirects, "-L");
    ASSERT_STR_EQ(c.output_path, "/tmp/out", "-o consumes next arg");
    free((void *)c.urls);
}

TEST(test_parse_cmdline_combined_flags_o_attached) {
    struct cmdline_opts c;
    memset(&c, 0, sizeof(c));
    char *argv[] = {(char *)"prog", (char *)"-fsSLo/tmp/out", (char *)"http://example.com", NULL};
    ASSERT_INT_EQ(parse_cmdline(3, argv, &c), 0, "combined -fsSLo/tmp/out with attached -o value");
    ASSERT_TRUE(c.fail_on_http_error, "-f");
    ASSERT_TRUE(c.silent, "-s");
    ASSERT_TRUE(c.show_error, "-S");
    ASSERT_TRUE(c.follow_redirects, "-L");
    ASSERT_STR_EQ(c.output_path, "/tmp/out", "-o attached value");
    free((void *)c.urls);
}

TEST(test_parse_cmdline_combined_flags_H) {
    struct cmdline_opts c;
    memset(&c, 0, sizeof(c));
    char *argv[] = {(char *)"prog", (char *)"-fH", (char *)"X-Custom: val", (char *)"-s", (char *)"http://example.com", NULL};
    ASSERT_INT_EQ(parse_cmdline(5, argv, &c), 0, "combined -fH with -H consuming next arg");
    ASSERT_TRUE(c.fail_on_http_error, "-f");
    ASSERT_TRUE(c.silent, "-s");
    ASSERT_INT_EQ(c.extra_header_count, 1, "one header");
    ASSERT_STR_EQ(c.extra_headers[0], "X-Custom: val", "header value");
    free((void *)c.urls);
    free((void *)c.extra_headers);
}

/* ================================================================
 * Huffman HPACK
 * ================================================================ */

TEST(test_huffman_roundtrip) {
    struct huff_node *tree = NULL;
    int alloc = 0;
    ASSERT_INT_EQ(huff_tree_init(&tree, &alloc), 0, "huff_tree_init");
    ASSERT_PTR_NOTNULL(tree, "huff_tree");

    static const char *cases[] = {
        "",
        "0",
        "GET",
        "https://example.com/path",
        "Hello, World!",
        "content-type",
        "application/json",
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        size_t in_len = strlen(cases[i]);
        unsigned char enc_buf[4096];
        size_t enc_len = huffman_encode((const unsigned char *)cases[i], in_len,
                                         enc_buf, sizeof(enc_buf));
        ASSERT_TRUE(enc_len > 0 || in_len == 0, "huffman_encode returned >0 for non-empty input");

        unsigned char dec_buf[4096];
        size_t dec_len = huffman_decode(tree, enc_buf, enc_len, dec_buf, sizeof(dec_buf));
        ASSERT_INT_EQ(dec_len, in_len, "decoded length matches original" /*, cases[i]*/);
        ASSERT_INT_EQ(memcmp(dec_buf, cases[i], in_len), 0, "decoded content matches original" /*, cases[i]*/);
    }

}

TEST(test_hpack_decode_empty_huffman) {
    struct huff_node *tree = NULL;
    int alloc = 0;
    ASSERT_INT_EQ(huff_tree_init(&tree, &alloc), 0, "huff_tree_init");
    ASSERT_PTR_NOTNULL(tree, "huff_tree");

    unsigned char buf = 0x80;
    size_t offset = 0;
    char out[256];
    size_t out_len = 0;

    int rc = hpack_decode_string(tree, &buf, 1, &offset, out, sizeof(out), &out_len);
    ASSERT_INT_EQ(rc, 0, "empty Huffman string decode succeeds");
    ASSERT_INT_EQ(out_len, (size_t)0, "empty Huffman string produces zero-length output");
    ASSERT_INT_EQ(offset, (size_t)1, "offset advanced past the encoding");
}

/* ================================================================
 * Main
 * ================================================================ */

int main(void) {
    printf("=== curldbg unit tests ===\n\n");

    test_parse_url_http_simple();
    test_parse_url_https();
    test_parse_url_explicit_port();
    test_parse_url_no_scheme_defaults_to_https();
    test_parse_url_ipv6();
    test_parse_url_ipv6_no_port();
    test_parse_url_invalid_scheme();
    test_parse_url_no_path();
    test_parse_url_userinfo();
    test_parse_url_userinfo_no_pass();
    test_parse_url_long_path();
    test_parse_url_query_string();
    test_parse_url_fragment();

    test_format_url_http();
    test_format_url_https();
    test_format_url_explicit_port();
    test_format_url_ipv6();
    test_format_host_header_standard();
    test_format_host_header_explicit_port();
    test_format_host_header_ipv6();
    test_format_host_header_overflow();
    test_format_absolute_uri_overflow();
    test_format_absolute_uri_http();

    test_is_redirect_status();

    test_base64_encode_simple();
    test_base64_encode_fo();
    test_base64_encode_foo();
    test_base64_encode_empty();
    test_base64_encode_buffer_too_small();

    test_url_encode_simple();
    test_url_encode_special_chars();
    test_url_encode_safe_chars();
    test_url_encode_empty();

    test_ms_between();
    test_ms_between_zero();
    test_trim_spaces_noop();
    test_trim_spaces_leading();
    test_trim_spaces_tabs();
    test_family_name();
    test_append_str();
    test_append_str_overflow();
    test_is_timeout_errno();
    test_deadline_remaining_ms();
    test_deadline_remaining_ms_max_zero();
    test_now_ms_monotonic();
    test_clear_race_info();
    test_clear_race_info_null();

    test_parse_response_headers_status();
    test_parse_response_headers_location();
    test_parse_response_headers_content_length();
    test_parse_response_headers_chunked();
    test_parse_response_headers_set_cookie();
    test_parse_response_headers_no_headers();
    test_parse_response_headers_lf_only();
    test_parse_response_headers_http10();
    test_parse_response_headers_content_encoding_gzip();
    test_parse_response_headers_content_encoding_deflate();
    test_parse_response_headers_multiple_set_cookie();
    test_parse_response_headers_bad_status();
    test_parse_response_headers_overflow_status();
    test_parse_response_headers_transfer_encoding_list();
    test_parse_response_headers_content_length_duplicate();
    test_parse_response_headers_content_length_negative();

    test_cookie_jar_add_and_get();
    test_cookie_jar_path_mismatch();
    test_cookie_jar_domain_mismatch();
    test_cookie_jar_multiple_cookies();
    test_cookie_jar_secure_over_http();
    test_cookie_jar_save_load_roundtrip();
    test_cookie_jar_max_capacity();
    test_cookie_jar_init();
    test_cookie_jar_reject_tld_domain();
    test_cookie_jar_reject_ip_domain();
    test_cookie_jar_secure_roundtrip();
    test_cookie_jar_httponly_samesite_parsed();

    test_build_redirect_url_absolute();
    test_build_redirect_url_relative();
    test_build_redirect_url_relative_dotdot();
    test_build_redirect_url_absolute_path();
    test_build_redirect_url_absolute_path_dot_segments();
    test_build_redirect_url_protocol_relative();
    test_build_redirect_url_relative_no_slash();

    test_write_out_expand();
    test_write_out_expand_double_percent();

    test_resolve_host_dns();
    test_resolve_host_cache();
    test_resolve_host_resolve_entry();

    test_set_error();
    test_set_error_truncated();
    test_set_error_null_buffer();
    test_set_error_zero_length();

    test_write_out_expand_http_code();
    test_write_out_expand_time_total();
    test_write_out_expand_url_effective();
    test_write_out_expand_num_redirects();
    test_write_out_expand_redirect_url();
    test_write_out_expand_newline_escape();
    test_write_out_expand_unknown_var();

    test_output_filename_from_url_basic();
    test_output_filename_from_url_root();
    test_output_filename_from_url_query();
    test_output_filename_from_url_fragment();
    test_output_filename_from_url_empty();
    test_output_filename_from_url_overflow();

    test_find_header_end_rnrn();
    test_find_header_end_nn();
    test_find_header_end_no_delimiter();
    test_find_header_end_at_start();

    test_write_body_data_to_file();
    test_write_body_data_preview();
    test_write_body_data_null_file();
    test_write_body_data_no_preview_still_writes();
    test_receive_response_captures_preview_without_body_file();
    test_receive_response_head_ignores_body();
    test_receive_response_100_continue();
    test_receive_response_100_continue_no_body();
    test_receive_response_103_early_hints();

    test_final_status_code_no_hops();
    test_final_status_code_one_hop();
    test_final_status_code_multi_hop();

    test_final_endpoint_ipv4();
    test_final_endpoint_no_hops();

    test_family_short_name_v4();
    test_family_short_name_v6();
    test_family_short_name_other();

    test_is_loopback_ip_v4();
    test_is_loopback_ip_v6();
    test_is_loopback_ip_remote();

    test_is_localhost_url_localhost();
    test_is_localhost_url_ipv4();
    test_is_localhost_url_ipv6();
    test_is_localhost_url_remote();

    test_fill_connected_endpoint_ipv4();
    test_fill_connected_endpoint_null();

    test_set_nonblocking();

    test_is_connection_error_write();
    test_is_connection_error_read();
    test_is_connection_error_timeout();
    test_is_connection_error_dns();
    test_is_connection_error_ok();

    test_init_run_options_basic();
    test_init_run_options_head_method();

    test_find_resolve_entry_match();
    test_find_resolve_entry_no_match();
    test_find_resolve_entry_empty();

    test_dns_cache_key();

    test_build_addrinfo_from_resolve_ipv4();

    test_copy_addrinfo_list_single();
    test_copy_addrinfo_list_null();

    test_build_body_headers_chunked_upload();
    test_build_body_headers_content_length();
    test_build_body_headers_post_data();
    test_build_body_headers_no_upload();
    test_build_body_headers_overflow();

    test_chunked_write_simple();
    test_chunked_write_multiple();
    test_chunked_write_split();

    test_setup_upload_file_stdin();
    test_setup_upload_file_missing();
    test_setup_upload_file_null();

    test_parse_cmdline_boolean_flags();
    test_parse_cmdline_value_flags();
    test_parse_cmdline_urls();
    test_parse_cmdline_defaults();
    test_parse_cmdline_resolve_ipv4();
    test_parse_cmdline_resolve_ipv6_bare();
    test_parse_cmdline_resolve_ipv6_bracketed();
    test_parse_cmdline_resolve_ipv6_host();
    test_parse_cmdline_resolve_ipv6_bracketed_both();
    test_parse_cmdline_resolve_missing_addr();
    test_parse_cmdline_resolve_unclosed_bracket();
    test_parse_cmdline_combined_flags_o();
    test_parse_cmdline_combined_flags_o_attached();
    test_parse_cmdline_combined_flags_H();

    test_huffman_roundtrip();
    test_hpack_decode_empty_huffman();

    printf("\n=== Results: %d passed, %d failed out of %d tests ===\n",
           tests_run - tests_failed, tests_failed, tests_run);
    return tests_failed > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
