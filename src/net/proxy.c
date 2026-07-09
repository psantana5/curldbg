#include "curldbg.h"

#include <stdio.h>
#include <string.h>

static char *find_connect_end(char *buf, size_t len) {
    for (size_t i = 0; i + 1 < len; i++) {
        if (buf[i] == '\n' && buf[i + 1] == '\n')
            return buf + i + 2;
        if (i + 3 < len && buf[i] == '\r' && buf[i + 1] == '\n' &&
            buf[i + 2] == '\r' && buf[i + 3] == '\n')
            return buf + i + 4;
    }
    return NULL;
}

int proxy_connect(struct connection *conn, const char *proxy_host, const char *proxy_port,
                  const struct url_info *target, int connect_timeout_ms,
                  char *error, size_t error_len) {
    (void)proxy_host;
    (void)proxy_port;
    (void)connect_timeout_ms;

    char request[2048];
    char response[4096];
    char host_header[320];
    size_t total = 0;

    format_host_header(target, host_header, sizeof(host_header));
    int nw = snprintf(request, sizeof(request), "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
                      host_header, host_header);
    if (nw < 0 || (size_t)nw >= sizeof(request)) {
        set_error(error, error_len, "CONNECT request too large"); return -1;
    }

    if (connection_write_all(conn, request, (size_t)nw, error, error_len) != 0) return -1;

    while (total < sizeof(response) - 1) {
        ssize_t n = connection_read(conn, response + total, sizeof(response) - 1 - total, error, error_len);
        if (n < 0) return -1;
        if (n == 0) break;
        size_t prev_total = total;
        total += (size_t)n;
        response[total] = '\0';
        size_t scan_start = (prev_total > 3) ? prev_total - 3 : 0;
        if (find_connect_end(response + scan_start, total - scan_start) != NULL) break;
    }

    response[total] = '\0';
    int status = 0;
    if (sscanf(response, "HTTP/%*d.%*d %d", &status) != 1) {
        set_error(error, error_len, "Invalid CONNECT response from proxy"); return -1;
    }

    if (status < 200 || status >= 300) {
        set_error(error, error_len, "Proxy CONNECT failed: HTTP %d", status); return -1;
    }

    return 0;
}
