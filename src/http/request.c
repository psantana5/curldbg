#define _GNU_SOURCE
#include "curldbg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

int build_body_headers(char *body_headers, size_t body_headers_size,
                               const char *verb, const char *data, size_t data_len,
                               const FILE *upload_file, size_t upload_size,
                               bool has_content_type, bool has_content_length,
                               bool chunked_upload, size_t *content_len_out,
                               bool *include_body_headers_out,
                               char *error, size_t error_len) {
    int n;
    *include_body_headers_out = false;
    *content_len_out = 0;
    body_headers[0] = '\0';

    if (__builtin_expect(upload_file != NULL, 0)) {
        *content_len_out = upload_size;
        *include_body_headers_out = true;
        if (chunked_upload) {
            if (has_content_type)
                n = snprintf(body_headers, body_headers_size, "Transfer-Encoding: chunked\r\n");
            else
                n = snprintf(body_headers, body_headers_size,
                    "Content-Type: application/octet-stream\r\n"
                    "Transfer-Encoding: chunked\r\n");
        } else if (has_content_type && has_content_length) {
            *include_body_headers_out = false;
            n = 0;
        } else if (has_content_type) {
            n = snprintf(body_headers, body_headers_size, "Content-Length: %zu\r\n", *content_len_out);
        } else if (has_content_length) {
            n = snprintf(body_headers, body_headers_size, "Content-Type: application/octet-stream\r\n");
        } else {
            n = snprintf(body_headers, body_headers_size,
                "Content-Type: application/octet-stream\r\n"
                "Content-Length: %zu\r\n", *content_len_out);
        }
        if (n < 0 || (size_t)n >= body_headers_size) {
            set_error(error, error_len, "Request body headers are too large"); return -1;
        }
    } else if (data != NULL || strcasecmp(verb, "POST") == 0 || strcasecmp(verb, "PUT") == 0) {
        *content_len_out = data_len;
        *include_body_headers_out = true;
        if (has_content_type && has_content_length) { *include_body_headers_out = false; n = 0; }
        else if (has_content_type) n = snprintf(body_headers, body_headers_size, "Content-Length: %zu\r\n", *content_len_out);
        else if (has_content_length) n = snprintf(body_headers, body_headers_size, "Content-Type: application/x-www-form-urlencoded\r\n");
        else n = snprintf(body_headers, body_headers_size,
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: %zu\r\n", *content_len_out);
        if (n < 0 || (size_t)n >= body_headers_size) {
            set_error(error, error_len, "Request body headers are too large"); return -1;
        }
    }
    return 0;
}

int build_request_buffer(const char *verb, size_t verb_len,
                                 const char *request_target, size_t request_target_len,
                                 const char *host_header, size_t host_header_len,
                                 const char *user_agent, size_t user_agent_len,
                                 const char *body_headers, size_t body_headers_len,
                                 bool include_body_headers,
                                 const char *auth_header, size_t auth_len,
                                 const char **extra_headers, size_t extra_header_count,
                                 bool has_host, bool compressed, bool has_accept_encoding,
                                 bool has_user_agent,
                                 char *req, size_t req_size,
                                 char *error, size_t error_len) {
    size_t offset = 0;
#define APPEND_MEM(p, l) do { \
        if (offset + (l) >= req_size) { \
            set_error(error, error_len, "Request is too large"); return -1; \
        } \
        memcpy(req + offset, (p), (l)); \
        offset += (l); \
    } while (0)

    APPEND_MEM(verb, verb_len);
    req[offset++] = ' ';
    APPEND_MEM(request_target, request_target_len);
    APPEND_MEM(" HTTP/1.1\r\n", 11);
    if (!has_host) {
        APPEND_MEM("Host: ", 6);
        APPEND_MEM(host_header, host_header_len);
        APPEND_MEM("\r\n", 2);
    }
    if (!has_user_agent) {
        APPEND_MEM("User-Agent: ", 12);
        APPEND_MEM(user_agent, user_agent_len);
        APPEND_MEM("\r\n", 2);
    }
    if (compressed && !has_accept_encoding) {
        APPEND_MEM("Accept-Encoding: gzip, deflate\r\n", 32);
    }
    if (include_body_headers && body_headers_len > 0) {
        APPEND_MEM(body_headers, body_headers_len);
    }
    if (auth_len > 0) {
        APPEND_MEM(auth_header, auth_len);
    }
    for (size_t i = 0; i < extra_header_count; i++) {
        if (extra_headers[i] == NULL) continue;
        size_t hlen = strlen(extra_headers[i]);
        APPEND_MEM(extra_headers[i], hlen);
        APPEND_MEM("\r\n", 2);
    }
    APPEND_MEM("\r\n", 2);
    req[offset] = '\0';
    return 0;
#undef APPEND_MEM
}

static int write_upload_body(struct connection *conn, FILE *upload_file,
                              bool chunked_upload, char *error, size_t error_len) {
    char buf[UPLOAD_READ_BUF];
    size_t nread;
    while ((nread = fread(buf, 1, sizeof(buf), upload_file)) > 0) {
        if (chunked_upload) {
            char chunk_hdr[32];
            int hn = snprintf(chunk_hdr, sizeof(chunk_hdr), "%zx\r\n", nread);
            const struct iovec iov[3] = {
                { .iov_base = chunk_hdr, .iov_len = (size_t)hn },
                { .iov_base = buf, .iov_len = nread },
                { .iov_base = "\r\n", .iov_len = 2 }
            };
            if (connection_writev_all(conn, iov, 3, error, error_len) != 0) return -1;
        } else {
            if (connection_write_all(conn, buf, nread, error, error_len) != 0) return -1;
        }
    }
    if (ferror(upload_file)) {
        set_error(error, error_len, "Failed to read upload file");
        return -1;
    }
    if (chunked_upload) {
        if (connection_write_all(conn, "0\r\n\r\n", 5, error, error_len) != 0) return -1;
    }
    return 0;
}

int send_request(
    struct connection *conn,
    const struct url_info *url,
    const char *method,
    const char *data,
    size_t data_len,
    FILE *upload_file,
    size_t upload_size,
    const char **extra_headers,
    size_t extra_header_count,
    const char *basic_auth,
    const char *user_agent,
    char *error,
    size_t error_len,
    bool use_proxy,
    bool chunked_upload,
    bool compressed,
    unsigned int header_flags
) {
    if (user_agent == NULL) user_agent = "curldbg/1.0";

    char host_header[320], body_headers[256], auth_header[1024];
    const char *verb = (method != NULL) ? method : "GET";
    size_t auth_len = 0, content_len = 0;
    bool include_body_headers = false;

    if (contains_crlf(verb) || contains_crlf(user_agent)) {
        set_error(error, error_len, "Request contains invalid characters"); return -1;
    }

    if (format_host_header(url, host_header, sizeof(host_header)) != 0) {
        set_error(error, error_len, "Host header too large"); return -1;
    }
    if (contains_crlf(host_header)) {
        set_error(error, error_len, "Host header contains invalid characters"); return -1;
    }


    bool has_content_type = (header_flags & HF_CONTENT_TYPE) != 0;
    bool has_content_length = (header_flags & HF_CONTENT_LENGTH) != 0;
    bool has_host = (header_flags & HF_HOST) != 0;
    bool has_accept_encoding = (header_flags & HF_ACCEPT_ENC) != 0;
    bool has_user_agent = (header_flags & HF_USER_AGENT) != 0;

    if (build_body_headers(body_headers, sizeof(body_headers), verb,
                           data, data_len, upload_file, upload_size,
                           has_content_type, has_content_length, chunked_upload,
                           &content_len, &include_body_headers,
                           error, error_len) != 0) return -1;

    {
        const char *effective_auth = basic_auth;
        char url_auth_buf[512];
        if (effective_auth == NULL || effective_auth[0] == '\0') {
            if (url->user[0] != '\0') {
                int na = snprintf(url_auth_buf, sizeof(url_auth_buf), "%s:%s", url->user, url->pass);
                if (na < 0 || (size_t)na >= sizeof(url_auth_buf)) {
                    set_error(error, error_len, "URL credentials are too large"); return -1;
                }
                effective_auth = url_auth_buf;
            }
        }
        if (effective_auth != NULL && effective_auth[0] != '\0') {
            if (contains_crlf(effective_auth)) {
                set_error(error, error_len, "Authorization value contains invalid characters"); return -1;
            }
            char auth_b64[512];
            if (base64_encode((const unsigned char *)effective_auth, strlen(effective_auth), auth_b64, sizeof(auth_b64)) != 0) {
                set_error(error, error_len, "Basic auth value is too large"); return -1;
            }
            int n = snprintf(auth_header, sizeof(auth_header), "Authorization: Basic %s\r\n", auth_b64);
            if (n < 0 || (size_t)n >= sizeof(auth_header)) {
                set_error(error, error_len, "Authorization header is too large"); return -1;
            }
            auth_len = (size_t)n;
        }
    }

    char proxy_abs_uri[2048];
    const char *request_target;
    if (use_proxy) {
        if (format_absolute_uri(url, proxy_abs_uri, sizeof(proxy_abs_uri)) != 0) {
            set_error(error, error_len, "Proxy request target too large"); return -1;
        }
        request_target = proxy_abs_uri;
    } else {
        request_target = url->path;
    }
    if (contains_crlf(request_target)) {
        set_error(error, error_len, "Request target contains invalid characters"); return -1;
    }

    for (size_t i = 0; i < extra_header_count; i++) {
        if (extra_headers[i] != NULL && contains_crlf(extra_headers[i])) {
            set_error(error, error_len, "Extra header contains invalid characters"); return -1;
        }
    }

    size_t verb_len = strlen(verb);
    size_t request_target_len = strlen(request_target);
    size_t host_header_len = strlen(host_header);
    size_t user_agent_len = strlen(user_agent);
    size_t body_headers_len = include_body_headers ? strlen(body_headers) : 0;

    char req[HEADER_MAX + 1];
    if (build_request_buffer(verb, verb_len, request_target, request_target_len,
                             host_header, host_header_len, user_agent, user_agent_len,
                             body_headers, body_headers_len, include_body_headers,
                             auth_header, auth_len,
                             extra_headers, extra_header_count,
                             has_host, compressed, has_accept_encoding,
                             has_user_agent,
                             req, sizeof(req), error, error_len) != 0) {
        return -1;
    }

    if (conn->verbose) {
        fprintf(stderr, "> %s %s HTTP/1.1\n", verb, request_target);
        if (!has_host) fprintf(stderr, "> Host: %s\n", host_header);
        if (!has_user_agent) fprintf(stderr, "> User-Agent: %s\n", user_agent);
        if (include_body_headers) {
            size_t off = 0;
            while (off < body_headers_len) {
                const char *end = strchr(body_headers + off, '\n');
                if (end == NULL) break;
                fprintf(stderr, "> ");
                fwrite(body_headers + off, 1, end - (body_headers + off) - (*(end-1)=='\r'?1:0), stderr);
                fputc('\n', stderr);
                off = end - body_headers + 1;
            }
        }
        if (auth_len > 0) fprintf(stderr, "> Authorization: Basic <redacted>\n");
        for (size_t i = 0; i < extra_header_count; i++) {
            if (extra_headers[i] != NULL) fprintf(stderr, "> %s\n", extra_headers[i]);
        }
        fprintf(stderr, ">\n");
    }

    size_t req_len = strlen(req);
    if (data_len > 0) {
        const struct iovec iov[2] = {
            { .iov_base = (void *)req, .iov_len = req_len },
            { .iov_base = (void *)data, .iov_len = data_len }
        };
        return connection_writev_all(conn, iov, 2, error, error_len);
    }
    if (connection_write_all(conn, req, req_len, error, error_len) != 0) return -1;

    if (upload_file != NULL)
        return write_upload_body(conn, upload_file, chunked_upload, error, error_len);

    return 0;
}
