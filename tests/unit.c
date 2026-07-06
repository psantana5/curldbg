#include "curldbg.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>

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

/* ================================================================
 * cookie_jar
 * ================================================================ */

TEST(test_cookie_jar_add_and_get) {
    struct cookie_jar jar;
    cookie_jar_init(&jar);
    cookie_jar_add_set_cookie(&jar, "session=abc; Path=/; Secure", "example.com");

    char header[512];
    cookie_jar_get_header(&jar, "example.com", "/", true, header, sizeof(header));
    ASSERT_STR_EQ(header, "session=abc", "cookie header sent to matching host");
}

TEST(test_cookie_jar_path_mismatch) {
    struct cookie_jar jar;
    cookie_jar_init(&jar);
    cookie_jar_add_set_cookie(&jar, "token=xyz; Path=/api", "example.com");

    char header[512];
    cookie_jar_get_header(&jar, "example.com", "/other", true, header, sizeof(header));
    ASSERT_STR_EQ(header, "", "cookie not sent for non-matching path");
}

TEST(test_cookie_jar_domain_mismatch) {
    struct cookie_jar jar;
    cookie_jar_init(&jar);
    cookie_jar_add_set_cookie(&jar, "key=val", "example.com");

    char header[512];
    cookie_jar_get_header(&jar, "other.com", "/", true, header, sizeof(header));
    ASSERT_STR_EQ(header, "", "cookie not sent for non-matching domain");
}

TEST(test_cookie_jar_multiple_cookies) {
    struct cookie_jar jar;
    cookie_jar_init(&jar);
    cookie_jar_add_set_cookie(&jar, "a=1", "example.com");
    cookie_jar_add_set_cookie(&jar, "b=2", "example.com");

    char header[512];
    cookie_jar_get_header(&jar, "example.com", "/", true, header, sizeof(header));
    ASSERT_TRUE(strstr(header, "a=1") != NULL, "first cookie present");
    ASSERT_TRUE(strstr(header, "b=2") != NULL, "second cookie present");
}

TEST(test_cookie_jar_secure_over_http) {
    struct cookie_jar jar;
    cookie_jar_init(&jar);
    cookie_jar_add_set_cookie(&jar, "session=abc; Path=/; Secure", "example.com");

    char header[512];
    cookie_jar_get_header(&jar, "example.com", "/", false, header, sizeof(header));
    ASSERT_STR_EQ(header, "", "secure cookie not sent over HTTP");

    cookie_jar_get_header(&jar, "example.com", "/", true, header, sizeof(header));
    ASSERT_STR_EQ(header, "session=abc", "secure cookie sent over HTTPS");
}

TEST(test_cookie_jar_save_load_roundtrip) {
    struct cookie_jar jar;
    cookie_jar_init(&jar);
    cookie_jar_add_set_cookie(&jar, "a=1; Path=/", "example.com");
    cookie_jar_add_set_cookie(&jar, "b=2; Path=/sub", "example.com");

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
}

TEST(test_cookie_jar_max_capacity) {
    struct cookie_jar jar;
    cookie_jar_init(&jar);
    char val[32];
    for (int i = 0; i < MAX_COOKIES + 10; i++) {
        snprintf(val, sizeof(val), "k%d=v%d; Path=/", i, i);
        cookie_jar_add_set_cookie(&jar, val, "example.com");
    }
    ASSERT_INT_EQ(jar.count, MAX_COOKIES, "cookie jar capped at MAX_COOKIES");
}

TEST(test_cookie_jar_init) {
    struct cookie_jar jar;
    jar.count = 999;
    cookie_jar_init(&jar);
    ASSERT_INT_EQ(jar.count, 0, "cookie_jar_init resets count");
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
    struct addrinfo *addrs = resolve_host(&url, AF_UNSPEC, NULL, 0, 5000,
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

    struct addrinfo *a1 = resolve_host(&url, AF_UNSPEC, NULL, 0, 5000,
                                        &dns_start, &dns_end, &gai_error);
    ASSERT_PTR_NOTNULL(a1, "resolve_host localhost first");
    freeaddrinfo(a1);

    struct addrinfo *a2 = resolve_host(&url, AF_UNSPEC, NULL, 0, 5000,
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
    struct addrinfo *addrs = resolve_host(&url, AF_UNSPEC, entries, 1, 5000,
                                           &dns_start, &dns_end, &gai_error);
    ASSERT_PTR_NOTNULL(addrs, "resolve_host custom resolve entry");
    ASSERT_INT_EQ(gai_error, 0, "gai_error 0 for resolve entry");
    ASSERT_INT_EQ(addrs->ai_family, AF_INET, "AF_INET from resolve entry");
    freeaddrinfo(addrs);
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

    test_cookie_jar_add_and_get();
    test_cookie_jar_path_mismatch();
    test_cookie_jar_domain_mismatch();
    test_cookie_jar_multiple_cookies();
    test_cookie_jar_secure_over_http();
    test_cookie_jar_save_load_roundtrip();
    test_cookie_jar_max_capacity();
    test_cookie_jar_init();

    test_build_redirect_url_absolute();
    test_build_redirect_url_relative();
    test_build_redirect_url_absolute_path();
    test_build_redirect_url_protocol_relative();
    test_build_redirect_url_relative_no_slash();

    test_write_out_expand();
    test_write_out_expand_double_percent();

    test_resolve_host_dns();
    test_resolve_host_cache();
    test_resolve_host_resolve_entry();

    printf("\n=== Results: %d passed, %d failed out of %d tests ===\n",
           tests_run - tests_failed, tests_failed, tests_run);
    return tests_failed > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
