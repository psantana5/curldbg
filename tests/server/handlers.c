#include "handlers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Each handler receives a raw fd.  It owns the entire response — the
 * framework never writes anything.  This avoids any abstraction that would
 * prevent producing intentionally malformed or unusual HTTP output.
 */

void handle_root(int fd, const struct request *req) {
    (void)req;
    dprintf(fd,
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 17\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "hello from testd");
}

void handle_404(int fd, const struct request *req) {
    (void)req;
    dprintf(fd,
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Length: 9\r\n"
        "\r\n"
        "not found");
}

void handle_500(int fd, const struct request *req) {
    (void)req;
    dprintf(fd,
        "HTTP/1.1 500 Internal Server Error\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "error");
}

/* --- Redirects --- */

void handle_redirect_prefixed(int fd, const struct request *req) {
    int count = 0;
    sscanf(req->path, "/redirect/%d", &count);
    if (count <= 0) count = 1;
    if (count <= 1)
        dprintf(fd, "HTTP/1.1 302 Found\r\nLocation: /final\r\n\r\n");
    else
        dprintf(fd, "HTTP/1.1 302 Found\r\nLocation: /redirect/%d\r\n\r\n", count - 1);
}

void handle_redirect_loop(int fd, const struct request *req) {
    (void)req;
    dprintf(fd, "HTTP/1.1 302 Found\r\nLocation: /redirect-loop\r\n\r\n");
}

void handle_infinite_redirect(int fd, const struct request *req) {
    (void)req;
    dprintf(fd,
        "HTTP/1.1 302 Found\r\n"
        "Location: /infinite-redirect\r\n"
        "\r\n");
}

/* --- Chunked transfer encoding --- */

void handle_chunked(int fd, const struct request *req) {
    (void)req;
    dprintf(fd,
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "4\r\n"
        "Wiki\r\n"
        "6\r\n"
        "pedia \r\n"
        "b\r\n"
        "in chunks.\r\n"
        "0\r\n"
        "\r\n");
}

void handle_bad_chunk(int fd, const struct request *req) {
    (void)req;
    dprintf(fd,
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "ZZZ\r\n"
        "garbage");
}

/* --- Gzip --- */

static const unsigned char gzip_body[] = {
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57,
    0x48, 0x2b, 0xca, 0xcf, 0x55, 0x48, 0xaf, 0xca,
    0x2c, 0x00, 0x00, 0x64, 0xaa, 0x8e, 0xb5, 0x0f,
    0x00, 0x00, 0x00,
};
/* decompresses to "hello from gzip" */

void handle_gzip(int fd, const struct request *req) {
    (void)req;
    dprintf(fd,
        "HTTP/1.1 200 OK\r\n"
        "Content-Encoding: gzip\r\n"
        "Content-Length: %zu\r\n"
        "\r\n", sizeof(gzip_body));
    write(fd, gzip_body, sizeof(gzip_body));
}

/* --- Cookies --- */

void handle_cookies(int fd, const struct request *req) {
    (void)req;
    dprintf(fd,
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 0\r\n"
        "Set-Cookie: session=abc123; Path=/; HttpOnly\r\n"
        "Set-Cookie: theme=dark; Path=/; Max-Age=3600\r\n"
        "\r\n");
}

/* --- Malformed / edge-case responses --- */

void handle_lf_only(int fd, const struct request *req) {
    (void)req;
    /* Unix line endings instead of \r\n */
    dprintf(fd,
        "HTTP/1.1 200 OK\n"
        "Content-Length: 5\n"
        "\n"
        "hello");
}

void handle_double_cl(int fd, const struct request *req) {
    (void)req;
    dprintf(fd,
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 5\r\n"
        "Content-Length: 10\r\n"
        "\r\n"
        "hello");
}

void handle_negative_cl(int fd, const struct request *req) {
    (void)req;
    dprintf(fd,
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: -1\r\n"
        "\r\n"
        "data");
}

void handle_slow_header(int fd, const struct request *req) {
    (void)req;
    /* Send status line immediately, then drip the rest */
    write(fd, "HTTP/1.1 200 OK\r\n", 17);
    usleep(150000);
    write(fd, "Content-Length: 5\r\n", 19);
    usleep(150000);
    write(fd, "\r\nhello", 8);
}

void handle_slow_body(int fd, const struct request *req) {
    (void)req;
    dprintf(fd,
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 25\r\n"
        "\r\n");
    fsync(fd);
    for (int i = 0; i < 5; i++) {
        usleep(150000);
        write(fd, ".....", 5);
    }
}

void handle_partial_body(int fd, const struct request *req) {
    (void)req;
    dprintf(fd,
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 100\r\n"
        "\r\n"
        "only 29 bytes of promised 100");
}

void handle_close_after_headers(int fd, const struct request *req) {
    (void)req;
    dprintf(fd,
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 999999\r\n"
        "\r\n");
    /* Server closes without sending body */
}

void handle_large_header(int fd, const struct request *req) {
    (void)req;
    dprintf(fd, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n");
    /* Emit ~10 KB of header fields */
    for (int i = 0; i < 200; i++)
        dprintf(fd, "X-Padding-%04d: %040d\r\n", i, i);
    dprintf(fd, "\r\nhello");
}

void handle_empty_response(int fd, const struct request *req) {
    (void)fd;
    (void)req;
    /* Close without sending anything */
}

void handle_premature_close(int fd, const struct request *req) {
    (void)req;
    dprintf(fd,
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 100\r\n"
        "\r\n"
        "partial");
    /* Close mid-body */
}

/* --- POST echo --- */

void handle_echo(int fd, const struct request *req) {
    (void)req;
    dprintf(fd,
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "posted");
}
