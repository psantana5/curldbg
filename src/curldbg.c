#include "curldbg.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/err.h>

void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

static void set_error(char *error, size_t error_len, const char *fmt, ...) {
    va_list args;
    if (error == NULL || error_len == 0) {
        return;
    }

    va_start(args, fmt);
    vsnprintf(error, error_len, fmt, args);
    va_end(args);
}

static void set_ssl_error(char *error, size_t error_len, const char *prefix) {
    unsigned long err = ERR_get_error();
    if (err != 0) {
        char openssl_msg[256];
        ERR_error_string_n(err, openssl_msg, sizeof(openssl_msg));
        set_error(error, error_len, "%s: %s", prefix, openssl_msg);
    } else {
        set_error(error, error_len, "%s", prefix);
    }
}

static bool is_timeout_errno(int err) {
    return err == EAGAIN || err == EWOULDBLOCK || err == ETIMEDOUT;
}

double ms_between(const struct timespec *start, const struct timespec *end) {
    double sec = (double)(end->tv_sec - start->tv_sec) * 1000.0;
    double nsec = (double)(end->tv_nsec - start->tv_nsec) / 1000000.0;
    return sec + nsec;
}

bool is_redirect_status(int status_code) {
    return status_code == 301 || status_code == 302 || status_code == 303 ||
           status_code == 307 || status_code == 308;
}

const char *family_name(int family) {
    if (family == AF_INET) {
        return "IPv4";
    }
    if (family == AF_INET6) {
        return "IPv6";
    }
    return "Unknown";
}

static void trim_spaces(char **start) {
    while (**start == ' ' || **start == '\t') {
        (*start)++;
    }
}

/* Parse http(s)://host[:port][/path] into host/port/path. */
int parse_url(const char *url, struct url_info *out) {
    const char *authority_start;
    const char *path_start;
    char authority[512];
    size_t authority_len;
    const char *http_prefix = "http://";
    const char *https_prefix = "https://";

    if (strncmp(url, http_prefix, strlen(http_prefix)) == 0) {
        authority_start = url + strlen(http_prefix);
        out->use_tls = false;
        strcpy(out->port, "80");
    } else if (strncmp(url, https_prefix, strlen(https_prefix)) == 0) {
        authority_start = url + strlen(https_prefix);
        out->use_tls = true;
        strcpy(out->port, "443");
    } else {
        fprintf(stderr, "Only http:// and https:// URLs are supported\n");
        return -1;
    }

    out->has_explicit_port = false;
    path_start = strchr(authority_start, '/');
    authority_len = path_start ? (size_t)(path_start - authority_start) : strlen(authority_start);

    if (authority_len == 0 || authority_len >= sizeof(authority)) {
        fprintf(stderr, "Invalid URL authority\n");
        return -1;
    }

    memcpy(authority, authority_start, authority_len);
    authority[authority_len] = '\0';

    if (authority[0] == '[') {
        char *closing = strchr(authority, ']');
        if (closing == NULL) {
            fprintf(stderr, "Invalid IPv6 host format\n");
            return -1;
        }

        *closing = '\0';
        if (strlen(authority + 1) >= sizeof(out->host)) {
            fprintf(stderr, "Host is too long\n");
            return -1;
        }
        strcpy(out->host, authority + 1);

        if (*(closing + 1) == ':') {
            if (strlen(closing + 2) == 0 || strlen(closing + 2) >= sizeof(out->port)) {
                fprintf(stderr, "Invalid port\n");
                return -1;
            }
            strcpy(out->port, closing + 2);
            out->has_explicit_port = true;
        } else if (*(closing + 1) != '\0') {
            fprintf(stderr, "Invalid authority format\n");
            return -1;
        }
    } else {
        char *colon = strrchr(authority, ':');
        if (colon != NULL) {
            *colon = '\0';
            if (strlen(colon + 1) == 0 || strlen(colon + 1) >= sizeof(out->port)) {
                fprintf(stderr, "Invalid port\n");
                return -1;
            }
            strcpy(out->port, colon + 1);
            out->has_explicit_port = true;
        }

        if (strlen(authority) == 0 || strlen(authority) >= sizeof(out->host)) {
            fprintf(stderr, "Invalid host\n");
            return -1;
        }
        strcpy(out->host, authority);
    }

    if (path_start == NULL) {
        strcpy(out->path, "/");
    } else {
        if (strlen(path_start) >= sizeof(out->path)) {
            fprintf(stderr, "Path is too long\n");
            return -1;
        }
        strcpy(out->path, path_start);
    }

    return 0;
}

static void parse_response_headers(char *headers, struct response_info *out) {
    char *line;
    char *line_end;

    out->status_code = 0;
    out->location[0] = '\0';

    line_end = strstr(headers, "\r\n");
    if (line_end == NULL) {
        return;
    }
    *line_end = '\0';
    if (sscanf(headers, "HTTP/%*d.%*d %d", &out->status_code) != 1) {
        out->status_code = 0;
    }

    line = line_end + 2;
    while (*line != '\0') {
        char *next = strstr(line, "\r\n");
        if (next == NULL) {
            break;
        }
        *next = '\0';

        if (strncasecmp(line, "Location:", 9) == 0) {
            char *value = line + 9;
            trim_spaces(&value);
            strncpy(out->location, value, sizeof(out->location) - 1);
            out->location[sizeof(out->location) - 1] = '\0';
            break;
        }

        line = next + 2;
    }
}

int build_redirect_url(
    const char *location,
    const struct url_info *base,
    char *out_url,
    size_t out_size
) {
    const char *scheme = base->use_tls ? "https" : "http";
    bool is_ipv6_literal = strchr(base->host, ':') != NULL;
    const char *path_to_use = base->path;
    char base_dir[1024];
    int n;

    if (strncmp(location, "http://", 7) == 0 || strncmp(location, "https://", 8) == 0) {
        if (strlen(location) >= out_size) {
            return -1;
        }
        strcpy(out_url, location);
        return 0;
    }

    if (location[0] != '/') {
        const char *slash = strrchr(base->path, '/');
        if (slash == NULL) {
            strcpy(base_dir, "/");
        } else {
            size_t keep = (size_t)(slash - base->path) + 1;
            if (keep >= sizeof(base_dir)) {
                return -1;
            }
            memcpy(base_dir, base->path, keep);
            base_dir[keep] = '\0';
        }

        if (snprintf(base_dir + strlen(base_dir), sizeof(base_dir) - strlen(base_dir), "%s", location) >=
            (int)(sizeof(base_dir) - strlen(base_dir))) {
            return -1;
        }
        path_to_use = base_dir;
    } else {
        path_to_use = location;
    }

    if (base->has_explicit_port) {
        if (is_ipv6_literal) {
            n = snprintf(out_url, out_size, "%s://[%s]:%s%s", scheme, base->host, base->port, path_to_use);
        } else {
            n = snprintf(out_url, out_size, "%s://%s:%s%s", scheme, base->host, base->port, path_to_use);
        }
    } else {
        if (is_ipv6_literal) {
            n = snprintf(out_url, out_size, "%s://[%s]%s", scheme, base->host, path_to_use);
        } else {
            n = snprintf(out_url, out_size, "%s://%s%s", scheme, base->host, path_to_use);
        }
    }

    if (n < 0 || (size_t)n >= out_size) {
        return -1;
    }
    return 0;
}

/* Resolve all candidate IPs (IPv4/IPv6) for host:port. */
struct addrinfo *resolve_dns(const struct url_info *url, int address_family, int *gai_error) {
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = address_family;
    hints.ai_socktype = SOCK_STREAM;

    rc = getaddrinfo(url->host, url->port, &hints, &result);
    if (rc != 0) {
        if (gai_error != NULL) {
            *gai_error = rc;
        }
        return NULL;
    }

    if (gai_error != NULL) {
        *gai_error = 0;
    }

    return result;
}

static int connect_with_timeout(int fd, const struct sockaddr *addr, socklen_t addrlen, int timeout_ms) {
    int flags;
    int rc;

    if (timeout_ms <= 0) {
        return connect(fd, addr, addrlen);
    }

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        return -1;
    }

    rc = connect(fd, addr, addrlen);
    if (rc == 0) {
        if (fcntl(fd, F_SETFL, flags) != 0) {
            return -1;
        }
        return 0;
    }
    if (errno != EINPROGRESS) {
        (void)fcntl(fd, F_SETFL, flags);
        return -1;
    }

    for (;;) {
        struct pollfd pfd;
        int poll_rc;
        int so_error = 0;
        socklen_t so_error_len = sizeof(so_error);

        pfd.fd = fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        poll_rc = poll(&pfd, 1, timeout_ms);
        if (poll_rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            (void)fcntl(fd, F_SETFL, flags);
            return -1;
        }
        if (poll_rc == 0) {
            errno = ETIMEDOUT;
            (void)fcntl(fd, F_SETFL, flags);
            return -1;
        }

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len) != 0) {
            (void)fcntl(fd, F_SETFL, flags);
            return -1;
        }
        if (so_error != 0) {
            errno = so_error;
            (void)fcntl(fd, F_SETFL, flags);
            return -1;
        }
        break;
    }

    if (fcntl(fd, F_SETFL, flags) != 0) {
        return -1;
    }
    return 0;
}

/* Try each resolved address until one connect() succeeds. */
int connect_tcp(
    const struct addrinfo *addrs,
    char *connected_ip,
    size_t connected_ip_size,
    int *connected_family,
    int connect_timeout_ms
) {
    const struct addrinfo *ai;
    int last_errno = 0;

    for (ai = addrs; ai != NULL; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            last_errno = errno;
            continue;
        }

        if (connect_with_timeout(fd, ai->ai_addr, ai->ai_addrlen, connect_timeout_ms) == 0) {
            if (getnameinfo(
                    ai->ai_addr,
                    ai->ai_addrlen,
                    connected_ip,
                    connected_ip_size,
                    NULL,
                    0,
                    NI_NUMERICHOST
                ) != 0) {
                strncpy(connected_ip, "unknown", connected_ip_size);
                connected_ip[connected_ip_size - 1] = '\0';
            }
            *connected_family = ai->ai_family;
            return fd;
        }

        last_errno = errno;
        close(fd);
    }

    if (last_errno != 0) {
        errno = last_errno;
    } else {
        errno = ECONNREFUSED;
    }
    return -1;
}

void apply_socket_timeout(int fd, int timeout_ms) {
    struct timeval tv;

    if (timeout_ms <= 0) {
        return;
    }

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
        die("setsockopt SO_RCVTIMEO");
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) {
        die("setsockopt SO_SNDTIMEO");
    }
}

void close_connection(struct connection *conn) {
    if (conn->ssl != NULL) {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
    if (conn->ctx != NULL) {
        SSL_CTX_free(conn->ctx);
        conn->ctx = NULL;
    }
    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }
}

int init_tls(struct connection *conn, const char *hostname, char *error, size_t error_len) {
    if (OPENSSL_init_ssl(0, NULL) != 1) {
        set_ssl_error(error, error_len, "OPENSSL_init_ssl failed");
        return -1;
    }

    conn->ctx = SSL_CTX_new(TLS_client_method());
    if (conn->ctx == NULL) {
        set_ssl_error(error, error_len, "SSL_CTX_new failed");
        return -1;
    }

#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
    SSL_CTX_set_options(conn->ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif

    SSL_CTX_set_verify(conn->ctx, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_set_default_verify_paths(conn->ctx) != 1) {
        set_ssl_error(error, error_len, "Could not load system CA certificates");
        return -1;
    }

    conn->ssl = SSL_new(conn->ctx);
    if (conn->ssl == NULL) {
        set_ssl_error(error, error_len, "SSL_new failed");
        return -1;
    }

    if (SSL_set_tlsext_host_name(conn->ssl, hostname) != 1) {
        set_ssl_error(error, error_len, "Failed to set TLS SNI hostname");
        return -1;
    }

    if (SSL_set1_host(conn->ssl, hostname) != 1) {
        set_ssl_error(error, error_len, "Failed to configure TLS hostname verification");
        return -1;
    }

    if (SSL_set_fd(conn->ssl, conn->fd) != 1) {
        set_ssl_error(error, error_len, "SSL_set_fd failed");
        return -1;
    }

    {
        int connect_rc = SSL_connect(conn->ssl);
        if (connect_rc != 1) {
            int ssl_err = SSL_get_error(conn->ssl, connect_rc);
            if ((ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) ||
                (ssl_err == SSL_ERROR_SYSCALL && is_timeout_errno(errno))) {
                set_error(error, error_len, "TLS handshake timeout");
                return -1;
            }
            if (ssl_err == SSL_ERROR_SYSCALL && errno != 0) {
                set_error(error, error_len, "TLS handshake failed: %s", strerror(errno));
                return -1;
            }
            if (ssl_err == SSL_ERROR_SYSCALL && errno == 0) {
                set_error(error, error_len, "TLS handshake failed: unexpected EOF");
                return -1;
            }

            set_ssl_error(error, error_len, "TLS handshake failed");
            return -1;
        }
    }

    if (SSL_get_verify_result(conn->ssl) != X509_V_OK) {
        set_error(error, error_len, "TLS certificate verification failed");
        return -1;
    }
    return 0;
}

static ssize_t connection_read(
    struct connection *conn,
    void *buf,
    size_t len,
    char *error,
    size_t error_len
) {
    if (!conn->use_tls) {
        ssize_t n = recv(conn->fd, buf, len, 0);
        if (n < 0) {
            if (is_timeout_errno(errno)) {
                set_error(error, error_len, "Read timeout");
                return -1;
            }
            set_error(error, error_len, "Read failed: %s", strerror(errno));
            return -1;
        }
        return n;
    }

    int n = SSL_read(conn->ssl, buf, (int)len);
    if (n > 0) {
        return n;
    }

    int ssl_err = SSL_get_error(conn->ssl, n);
    if (ssl_err == SSL_ERROR_ZERO_RETURN) {
        return 0;
    }
    if ((ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) ||
        (ssl_err == SSL_ERROR_SYSCALL && is_timeout_errno(errno))) {
        set_error(error, error_len, "Read timeout");
        return -1;
    }
    if (ssl_err == SSL_ERROR_SYSCALL && errno != 0) {
        set_error(error, error_len, "Read failed: %s", strerror(errno));
        return -1;
    }
    if (ssl_err == SSL_ERROR_SYSCALL && errno == 0) {
        return 0;
    }

    set_ssl_error(error, error_len, "SSL_read failed");
    return -1;
}

static int connection_write_all(
    struct connection *conn,
    const char *buf,
    size_t len,
    char *error,
    size_t error_len
) {
    size_t sent = 0;

    while (sent < len) {
        if (!conn->use_tls) {
            ssize_t n = send(conn->fd, buf + sent, len - sent, 0);
            if (n < 0) {
                if (is_timeout_errno(errno)) {
                    set_error(error, error_len, "Write timeout");
                } else {
                    set_error(error, error_len, "Write failed: %s", strerror(errno));
                }
                return -1;
            }
            sent += (size_t)n;
            continue;
        }

        int n = SSL_write(conn->ssl, buf + sent, (int)(len - sent));
        if (n <= 0) {
            int ssl_err = SSL_get_error(conn->ssl, n);
            if ((ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) ||
                (ssl_err == SSL_ERROR_SYSCALL && is_timeout_errno(errno))) {
                set_error(error, error_len, "Write timeout");
                return -1;
            }
            if (ssl_err == SSL_ERROR_SYSCALL && errno != 0) {
                set_error(error, error_len, "Write failed: %s", strerror(errno));
                return -1;
            }
            if (ssl_err == SSL_ERROR_SYSCALL && errno == 0) {
                set_error(error, error_len, "Write failed: unexpected EOF");
                return -1;
            }
            set_ssl_error(error, error_len, "SSL_write failed");
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

static void format_host_header(const struct url_info *url, char *out, size_t out_size) {
    bool is_ipv6_literal = strchr(url->host, ':') != NULL;

    if (url->has_explicit_port) {
        if (is_ipv6_literal) {
            snprintf(out, out_size, "[%s]:%s", url->host, url->port);
        } else {
            snprintf(out, out_size, "%s:%s", url->host, url->port);
        }
        return;
    }

    if (is_ipv6_literal) {
        snprintf(out, out_size, "[%s]", url->host);
    } else {
        snprintf(out, out_size, "%s", url->host);
    }
}

/* Send a minimal HTTP/1.1 GET request. */
int send_request(struct connection *conn, const struct url_info *url, char *error, size_t error_len) {
    char req[2048];
    char host_header[320];
    size_t req_len;
    int n;

    format_host_header(url, host_header, sizeof(host_header));

    n = snprintf(
        req,
        sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: curldbg/1.0\r\n"
        "Connection: close\r\n"
        "\r\n",
        url->path,
        host_header
    );

    if (n < 0 || (size_t)n >= sizeof(req)) {
        set_error(error, error_len, "Request is too large");
        return -1;
    }

    req_len = (size_t)n;
    return connection_write_all(conn, req, req_len, error, error_len);
}

/* Find the end of HTTP headers in a byte buffer (\r\n\r\n). */
static char *find_header_end(char *buf, size_t len) {
    size_t i;
    if (len < 4) {
        return NULL;
    }

    for (i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return buf + i + 4;
        }
    }
    return NULL;
}

/*
 * Read response until EOF.
 * - Measures TTFB from ttfb_start to first recv()/SSL_read() data
 * - Captures first ~1KB of body (headers are stripped)
 */
int receive_response(
    struct connection *conn,
    const struct timespec *ttfb_start,
    struct response_info *out,
    char *error,
    size_t error_len
) {
    char recv_buf[4096];
    char header_buf[HEADER_MAX + 1];
    size_t header_len = 0;
    bool header_done = false;
    bool seen_first_byte = false;
    struct timespec first_byte_ts;

    memset(out, 0, sizeof(*out));

    for (;;) {
        ssize_t n = connection_read(conn, recv_buf, sizeof(recv_buf), error, error_len);
        if (n < 0) {
            return -1;
        }
        if (n == 0) {
            break;
        }

        if (!seen_first_byte) {
            if (clock_gettime(CLOCK_MONOTONIC, &first_byte_ts) != 0) {
                set_error(error, error_len, "clock_gettime failed");
                return -1;
            }
            out->ttfb_ms = ms_between(ttfb_start, &first_byte_ts);
            seen_first_byte = true;
        }

        if (!header_done) {
            if (header_len + (size_t)n >= sizeof(header_buf)) {
                set_error(error, error_len, "Response headers too large");
                return -1;
            }
            memcpy(header_buf + header_len, recv_buf, (size_t)n);
            header_len += (size_t)n;
            header_buf[header_len] = '\0';

            char *body_start = find_header_end(header_buf, header_len);
            if (body_start != NULL) {
                size_t header_bytes = (size_t)(body_start - header_buf);
                size_t body_available = header_len - header_bytes;
                size_t take = body_available;
                char headers_only[HEADER_MAX + 1];

                memcpy(headers_only, header_buf, header_bytes);
                headers_only[header_bytes] = '\0';
                parse_response_headers(headers_only, out);

                if (take > PREVIEW_BYTES - out->preview_len) {
                    take = PREVIEW_BYTES - out->preview_len;
                }
                memcpy(out->preview + out->preview_len, body_start, take);
                out->preview_len += take;
                header_done = true;
            }
            continue;
        }

        if (out->preview_len < PREVIEW_BYTES) {
            size_t take = (size_t)n;
            if (take > PREVIEW_BYTES - out->preview_len) {
                take = PREVIEW_BYTES - out->preview_len;
            }
            memcpy(out->preview + out->preview_len, recv_buf, take);
            out->preview_len += take;
        }
    }

    out->preview[out->preview_len] = '\0';
    if (!seen_first_byte) {
        out->ttfb_ms = -1.0;
    }
    return 0;
}
