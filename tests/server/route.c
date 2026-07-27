#include "route.h"
#include "handlers.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SZ(a) (sizeof(a) - 1)

int route_parse(int fd, struct request *req) {
    char buf[REQ_BUF_MAX];
    size_t pos = 0;
    int headers_done = 0;

    memset(req, 0, sizeof(*req));
    req->minor_version = 1;

    while (pos < sizeof(buf) - 1) {
        char c;
        ssize_t n = read(fd, &c, 1);
        if (n <= 0) return -1;
        buf[pos++] = c;
        if (pos >= 4 && buf[pos-4] == '\r' && buf[pos-3] == '\n'
                    && buf[pos-2] == '\r' && buf[pos-1] == '\n') {
            headers_done = 1;
            break;
        }
        if (pos >= 2 && buf[pos-2] == '\n' && buf[pos-1] == '\n') {
            headers_done = 1;
            break;
        }
    }
    if (!headers_done) return -1;
    buf[pos] = '\0';

    /* Parse request line: METHOD SP PATH SP HTTP/1.X */
    const char *sp1 = strchr(buf, ' ');
    if (!sp1) return -1;
    size_t method_len = (size_t)(sp1 - buf);
    if (method_len >= sizeof(req->method)) return -1;
    memcpy(req->method, buf, method_len);

    const char *sp2 = strchr(sp1 + 1, ' ');
    if (!sp2) {
        /* tolerate missing HTTP version */
        size_t path_len = strlen(sp1 + 1);
        if (path_len >= REQ_PATH_MAX) return -1;
        memcpy(req->path, sp1 + 1, path_len);
        return 0;
    }
    size_t path_len = (size_t)(sp2 - sp1 - 1);
    if (path_len >= REQ_PATH_MAX) return -1;
    memcpy(req->path, sp1 + 1, path_len);

    /* HTTP version */
    if (strncmp(sp2 + 1, "HTTP/1.", 7) == 0)
        req->minor_version = (sp2[8] == '1') ? 1 : 0;

    return 0;
}

static const struct route g_routes[] = {
    {"GET",  "/",                          handle_root},
    {"GET",  "/final",                     handle_root},
    {"GET",  "/404",                       handle_404},
    {"GET",  "/500",                       handle_500},
    {"GET",  "/redirect-loop",             handle_redirect_loop},
    {"GET",  "/redirect*",                 handle_redirect_prefixed},
    {"GET",  "/chunked",                   handle_chunked},
    {"GET",  "/bad-chunk",                 handle_bad_chunk},
    {"GET",  "/gzip",                      handle_gzip},
    {"GET",  "/cookies",                   handle_cookies},
    {"GET",  "/lf-only",                   handle_lf_only},
    {"GET",  "/double-content-length",     handle_double_cl},
    {"GET",  "/negative-content-length",   handle_negative_cl},
    {"GET",  "/slow-header",               handle_slow_header},
    {"GET",  "/slow-body",                 handle_slow_body},
    {"GET",  "/partial-body",              handle_partial_body},
    {"GET",  "/close-after-headers",       handle_close_after_headers},
    {"GET",  "/large-header",              handle_large_header},
    {"GET",  "/empty-response",            handle_empty_response},
    {"GET",  "/premature-close",           handle_premature_close},
    {"GET",  "/infinite-redirect",         handle_infinite_redirect},
    {"POST", "/echo",                      handle_echo},
    {NULL,   NULL,                         NULL},
};

void route_dispatch(int fd, const struct request *req) {
    for (const struct route *r = g_routes; r->method != NULL; r++) {
        if (strcmp(req->method, r->method) != 0) continue;
        size_t route_len = strlen(r->path);
        int prefix = (route_len > 0 && r->path[route_len - 1] == '*');
        size_t match_len = prefix ? route_len - 1 : route_len;
        if (strncmp(req->path, r->path, match_len) == 0) {
            if (!prefix && req->path[match_len] != '\0') continue;
            r->handler(fd, req);
            return;
        }
    }
    handle_404(fd, req);
}
