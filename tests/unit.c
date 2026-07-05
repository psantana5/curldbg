#include "curldbg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

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

/* --- parse_url tests --- */
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

/* --- is_redirect_status tests --- */
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

/* --- base64_encode tests --- */
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

/* --- url_encode tests --- */
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

/* --- parse_response_headers tests --- */
/* parse_response_headers uses memchr(..., HEADER_MAX) so needs full buffer */
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

/* --- cookie_jar tests --- */
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

/* --- write_out_expand tests --- */
/* redirect stdout temporarily during write_out_expand */
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

/* --- build_redirect_url tests --- */
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

    test_parse_response_headers_status();
    test_parse_response_headers_location();
    test_parse_response_headers_content_length();
    test_parse_response_headers_chunked();
    test_parse_response_headers_set_cookie();
    test_parse_response_headers_no_headers();
    test_parse_response_headers_lf_only();

    test_cookie_jar_add_and_get();
    test_cookie_jar_path_mismatch();
    test_cookie_jar_domain_mismatch();
    test_cookie_jar_multiple_cookies();
    test_cookie_jar_secure_over_http();

    test_build_redirect_url_absolute();
    test_build_redirect_url_relative();
    test_build_redirect_url_absolute_path();
    test_build_redirect_url_protocol_relative();

    test_write_out_expand();

    printf("\n=== Results: %d passed, %d failed out of %d tests ===\n",
           tests_run - tests_failed, tests_failed, tests_run);
    return tests_failed > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
