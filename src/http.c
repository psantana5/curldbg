#define _GNU_SOURCE
#include "curldbg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <zlib.h>

bool is_redirect_status(int status_code) {
    return status_code == 301 || status_code == 302 || status_code == 303 ||
           status_code == 307 || status_code == 308;
}

void parse_response_headers(char *headers, struct response_info *out) {
    out->status_code = 0;
    out->location[0] = '\0';
    out->chunked = false;
    out->content_length = -1;
    out->set_cookie_buf[0] = '\0';
    out->set_cookie_len = 0;

    char *nl = (char *)memchr(headers, '\n', HEADER_MAX);
    if (nl == NULL || nl == headers) return;
    if (*(nl - 1) == '\r') *(nl - 1) = '\0';
    *nl = '\0';
    if (sscanf(headers, "HTTP/%*d.%*d %d", &out->status_code) != 1 &&
        sscanf(headers, "HTTP/%*d %d", &out->status_code) != 1) {
        out->status_code = 0; return;
    }

    char *line = nl + 1;
    size_t remaining = HEADER_MAX - (size_t)(line - headers);
    while (remaining > 0 && *line != '\0') {
        nl = (char *)memchr(line, '\n', remaining);
        if (nl == NULL) break;
        size_t line_len = (size_t)(nl - line);
        if (line_len > 0 && *(nl - 1) == '\r') { *(nl - 1) = '\0'; line_len--; }
        *nl = '\0';

        if (line_len >= 9) {
            switch (line[0] | 32) {
            case 'l':
                if (strncasecmp(line, "Location:", 9) == 0) {
                    char *value = line + 9;
                    trim_spaces(&value);
                    strncpy(out->location, value, sizeof(out->location) - 1);
                    out->location[sizeof(out->location) - 1] = '\0';
                }
                break;
            case 'c':
                if (line_len >= 15 && strncasecmp(line, "Content-Length:", 15) == 0) {
                    const char *val = line + 15;
                    trim_spaces((char **)&val);
                    char *end = NULL;
                    long cl = strtol(val, &end, 10);
                    if (*end == '\0' && cl >= 0) out->content_length = cl;
                } else if (line_len >= 16 && strncasecmp(line, "Content-Encoding:", 16) == 0) {
                    const char *val = line + 16;
                    trim_spaces((char **)&val);
                    strncpy(out->content_encoding, val, sizeof(out->content_encoding) - 1);
                    out->content_encoding[sizeof(out->content_encoding) - 1] = '\0';
                }
                break;
            case 't':
                if (line_len >= 18 && strncasecmp(line, "Transfer-Encoding:", 18) == 0) {
                    const char *val = line + 18;
                    trim_spaces((char **)&val);
                    if (strcasecmp(val, "chunked") == 0) out->chunked = true;
                }
                break;
            case 's':
                if (line_len >= 12 && strncasecmp(line, "Set-Cookie:", 11) == 0) {
                    const char *val = line + 11;
                    trim_spaces((char **)&val);
                    size_t vlen = strlen(val);
                    if (out->set_cookie_len + vlen + 1 < sizeof(out->set_cookie_buf)) {
                        if (out->set_cookie_len > 0) out->set_cookie_buf[out->set_cookie_len++] = '\n';
                        memcpy(out->set_cookie_buf + out->set_cookie_len, val, vlen);
                        out->set_cookie_len += vlen;
                        out->set_cookie_buf[out->set_cookie_len] = '\0';
                    }
                }
                break;
            }  /* end switch */
        }

        line = nl + 1;
        remaining = HEADER_MAX - (size_t)(line - headers);
    }
}

static char *find_header_end(char *buf, size_t len) {
    for (size_t i = 0; i + 1 < len; i++) {
        if (buf[i] == '\n' && buf[i + 1] == '\n')
            return buf + i + 2;
        if (i + 3 < len && buf[i] == '\r' && buf[i + 1] == '\n' &&
            buf[i + 2] == '\r' && buf[i + 3] == '\n')
            return buf + i + 4;
    }
    return NULL;
}

static size_t write_body_data(const char *buf, size_t len, FILE *body_out, struct response_info *out) {
    if (body_out != NULL && len > 0) {
        if (fwrite(buf, 1, len, body_out) != len) return (size_t)-1;
    }
    if (out->preview_len < PREVIEW_BYTES) {
        size_t take = len;
        if (take > PREVIEW_BYTES - out->preview_len) take = PREVIEW_BYTES - out->preview_len;
        memcpy(out->preview + out->preview_len, buf, take);
        out->preview_len += take;
    }
    return 0;
}

static size_t write_body_maybe_decomp(const char *buf, size_t len, FILE *body_out,
                                       struct response_info *out, z_stream *strm,
                                       bool decompress, char *error, size_t error_len) {
    if (!decompress || strm == NULL)
        return write_body_data(buf, len, body_out, out);

    strm->next_in = (unsigned char *)buf;
    strm->avail_in = (unsigned int)len;
    do {
        unsigned char obuf[RESPONSE_READ_BUF];
        strm->next_out = obuf;
        strm->avail_out = sizeof(obuf);
        int ret = inflate(strm, Z_NO_FLUSH);
        if (ret < 0 && ret != Z_BUF_ERROR) {
            set_error(error, error_len, "Decompression failed");
            return (size_t)-1;
        }
        size_t have = sizeof(obuf) - strm->avail_out;
        if (have > 0) {
            if (write_body_data((char *)obuf, have, body_out, out) == (size_t)-1) {
                set_error(error, error_len, "Failed to write response body");
                return (size_t)-1;
            }
        }
    } while (strm->avail_out == 0);
    return 0;
}

static size_t chunked_write(const char *buf, size_t len, FILE *body_out, struct response_info *out,
                            int *state, unsigned long *chunk_rem, char *line_buf, size_t *line_len,
                            z_stream *decomp_strm, bool decompress, char *error, size_t error_len) {
    size_t consumed = 0;
    while (consumed < len) {
        if (*state == 0) {
            while (consumed < len && buf[consumed] != '\n') {
                if (buf[consumed] != '\r' && *line_len < 31)
                    line_buf[(*line_len)++] = buf[consumed];
                consumed++;
            }
            if (consumed < len && buf[consumed] == '\n') {
                consumed++;
                line_buf[*line_len] = '\0';
                char *semi = strchr(line_buf, ';');
                if (semi) *semi = '\0';
                char *end = NULL;
                *chunk_rem = (unsigned long)strtoul(line_buf, &end, 16);
                *line_len = 0;
                if (*chunk_rem == 0) *state = 3;
                else *state = 1;
            }
        } else if (*state == 1) {
            size_t take = len - consumed;
            if (take > *chunk_rem) take = (size_t)*chunk_rem;
            if (write_body_maybe_decomp(buf + consumed, take, body_out, out,
                                         decomp_strm, decompress, error, error_len) == (size_t)-1)
                return (size_t)-1;
            consumed += take;
            *chunk_rem -= (unsigned long)take;
            if (*chunk_rem == 0) *state = 2;
        } else if (*state == 2) {
            if (buf[consumed] == '\r') consumed++;
            else if (buf[consumed] == '\n') { consumed++; *state = 0; }
            else *state = 0;
        } else {
            break;
        }
    }
    return consumed;
}

static int build_body_headers(char *body_headers, size_t body_headers_size,
                               const char *verb, const char *data, size_t data_len,
                               FILE *upload_file, size_t upload_size,
                               bool has_content_type, bool has_content_length,
                               bool chunked_upload, size_t *content_len_out,
                               bool *include_body_headers_out,
                               char *error, size_t error_len) {
    int n;
    *include_body_headers_out = false;
    *content_len_out = 0;
    body_headers[0] = '\0';

    if (upload_file != NULL) {
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

static int build_request_buffer(const char *verb, size_t verb_len,
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
            struct iovec iov[3] = {
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
    bool compressed
) {
    if (user_agent == NULL) user_agent = "curldbg/1.0";

    char host_header[320], body_headers[256], auth_header[1024], auth_b64[512];
    const char *verb = (method != NULL) ? method : "GET";
    size_t auth_len = 0, content_len = 0;
    bool include_body_headers = false;
    int n;

    format_host_header(url, host_header, sizeof(host_header));

    bool has_content_type = false, has_content_length = false, has_host = false,
         has_accept_encoding = false, has_user_agent = false;
    for (size_t i = 0; i < extra_header_count; i++) {
        if (extra_headers[i] == NULL) continue;
        if (strncasecmp(extra_headers[i], "Content-Type:", 13) == 0) has_content_type = true;
        else if (strncasecmp(extra_headers[i], "Content-Length:", 15) == 0) has_content_length = true;
        else if (strncasecmp(extra_headers[i], "Host:", 5) == 0) has_host = true;
        else if (strncasecmp(extra_headers[i], "Accept-Encoding:", 16) == 0) has_accept_encoding = true;
        else if (strncasecmp(extra_headers[i], "User-Agent:", 11) == 0) has_user_agent = true;
    }

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
            if (base64_encode((const unsigned char *)effective_auth, strlen(effective_auth), auth_b64, sizeof(auth_b64)) != 0) {
                set_error(error, error_len, "Basic auth value is too large"); return -1;
            }
            n = snprintf(auth_header, sizeof(auth_header), "Authorization: Basic %s\r\n", auth_b64);
            if (n < 0 || (size_t)n >= sizeof(auth_header)) {
                set_error(error, error_len, "Authorization header is too large"); return -1;
            }
            auth_len = (size_t)n;
        }
    }

    char proxy_abs_uri[2048];
    const char *request_target;
    if (use_proxy) {
        format_absolute_uri(url, proxy_abs_uri, sizeof(proxy_abs_uri));
        request_target = proxy_abs_uri;
    } else {
        request_target = url->path;
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
        struct iovec iov[2] = {
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

/*
 * Read response body until Content-Length or EOF.
 * - Measures TTFB from ttfb_start to first recv()/SSL_read() data
 * - Captures first ~1KB of body (headers are stripped)
 */
int receive_response(
    struct connection *conn,
    const struct timespec *ttfb_start,
    struct response_info *out,
    char *error, size_t error_len,
    FILE *body_out,
    bool follow_redirects,
    bool fail_on_http_error,
    bool head_method
) {
    (void)follow_redirects;
    (void)fail_on_http_error;

    char recv_buf[RESPONSE_READ_BUF];
    char header_buf[HEADER_MAX + 1];
    size_t header_len = 0;
    bool header_done = false;
    bool seen_first_byte = false;
    bool write_body = body_out != NULL;
    struct timespec first_byte_ts;
    bool chunked = false;
    int chunk_state = 0;
    unsigned long chunk_remaining = 0;
    char chunk_line_buf[32];
    size_t chunk_line_len = 0;
    bool trailer_mode = false;
    long body_remaining = -1;
    bool need_decompress = false;
    z_stream decomp_strm;
    bool decomp_init = false;

    memset(out, 0, sizeof(*out));

    for (;;) {
        ssize_t n = connection_read(conn, recv_buf, sizeof(recv_buf), error, error_len);
        if (n < 0) return -1;
        if (n == 0) break;

        if (!seen_first_byte) {
            if (clock_gettime(CLOCK_MONOTONIC, &first_byte_ts) != 0) {
                set_error(error, error_len, "clock_gettime failed"); return -1;
            }
            out->ttfb_ms = ms_between(ttfb_start, &first_byte_ts);
            seen_first_byte = true;
        }

        if (!header_done) {
            size_t hbuf_room = sizeof(header_buf) - header_len - 1;
            size_t hbuf_take = (size_t)n;
            size_t recv_excess = 0;
            if (hbuf_take > hbuf_room) { hbuf_take = hbuf_room; recv_excess = (size_t)n - hbuf_take; }
            memcpy(header_buf + header_len, recv_buf, hbuf_take);
            header_len += hbuf_take;
            header_buf[header_len] = '\0';

            char *body_start = find_header_end(header_buf, header_len);
            if (body_start != NULL) {
                size_t header_bytes = (size_t)(body_start - header_buf);
                size_t body_in_hbuf = header_len - header_bytes;

                char pending_body[RESPONSE_READ_BUF];
                size_t pending_len = 0;
                if (body_in_hbuf > 0) { memcpy(pending_body, body_start, body_in_hbuf); pending_len = body_in_hbuf; }
                if (recv_excess > 0) { memcpy(pending_body + pending_len, recv_buf + hbuf_take, recv_excess); pending_len += recv_excess; }

                if (conn->verbose) {
                    char headers_only[HEADER_MAX + 1];
                    memcpy(headers_only, header_buf, header_bytes);
                    headers_only[header_bytes] = '\0';
                    char *line = headers_only;
                    while (*line != '\0') {
                        char *nl = strstr(line, "\r\n");
                        if (nl == NULL) break;
                        *nl = '\0';
                        fprintf(stderr, "< %s\n", line);
                        line = nl + 2;
                    }
                }
                header_buf[header_bytes] = '\0';

                parse_response_headers(header_buf, out);

                if (out->status_code == 0) {
                    set_error(error, error_len, "Invalid HTTP response status line");
                    if (decomp_init) inflateEnd(&decomp_strm);
                    return -1;
                }

                if (head_method) return 0;

                if (out->content_encoding[0] != '\0' &&
                    (strcasecmp(out->content_encoding, "gzip") == 0 ||
                     strcasecmp(out->content_encoding, "deflate") == 0)) {
                    memset(&decomp_strm, 0, sizeof(decomp_strm));
                    if (inflateInit2(&decomp_strm, 15 + 32) != Z_OK) {
                        set_error(error, error_len, "Failed to init decompression");
                        return -1;
                    }
                    need_decompress = true;
                    decomp_init = true;
                }

                chunked = out->chunked;
                body_remaining = out->content_length;
                if (chunked) {
                    size_t cw = chunked_write(pending_body, pending_len, write_body ? body_out : NULL, out,
                                      &chunk_state, &chunk_remaining, chunk_line_buf, &chunk_line_len,
                                      need_decompress ? &decomp_strm : NULL, need_decompress,
                                      error, error_len);
                    if (cw == (size_t)-1) { if (decomp_init) inflateEnd(&decomp_strm); return -1; }
                    if (chunk_state == 3 && cw < pending_len) {
                        size_t off = cw;
                        while (off < pending_len) {
                            const char *cr = memchr(pending_body + off, '\r', pending_len - off);
                            if (cr == NULL) break;
                            size_t cr_off = (size_t)(cr - pending_body);
                            if (cr_off + 1 < pending_len && pending_body[cr_off + 1] == '\n') {
                                bool empty = (cr_off == off);
                                off = cr_off + 2;
                                if (empty) break;
                            } else if (cr_off + 1 >= pending_len) {
                                trailer_mode = true; break;
                            } else {
                                off = cr_off + 1;
                            }
                        }
                    }
                } else if (pending_len > 0) {
                    if (write_body_maybe_decomp(pending_body, pending_len, write_body ? body_out : NULL, out,
                                                 need_decompress ? &decomp_strm : NULL, need_decompress,
                                                 error, error_len) == (size_t)-1) {
                        if (decomp_init) { inflateEnd(&decomp_strm); } return -1;
                    }
                    if (body_remaining > 0) body_remaining -= (long)pending_len;
                }
                header_done = true;
                if (!chunked && body_remaining <= 0) break;
            } else if (header_len >= sizeof(header_buf) - 1) {
                set_error(error, error_len, "Response headers too large"); return -1;
            }
            continue;
        }

        if (chunked) {
            if (trailer_mode) {
                size_t off = 0;
                while (off < (size_t)n) {
                    const char *cr = memchr(recv_buf + off, '\r', (size_t)n - off);
                    if (cr == NULL) break;
                    size_t cr_off = (size_t)(cr - recv_buf);
                    if (cr_off + 1 < (size_t)n && recv_buf[cr_off + 1] == '\n') {
                        off = cr_off + 2;
                        if (cr_off == off - 2) { trailer_mode = false; break; }
                    } else if (cr_off + 1 >= (size_t)n) {
                        break;
                    } else {
                        off = cr_off + 1;
                    }
                }
                if (trailer_mode) break;
                continue;
            }
            size_t cw = chunked_write(recv_buf, (size_t)n, write_body ? body_out : NULL, out,
                              &chunk_state, &chunk_remaining, chunk_line_buf, &chunk_line_len,
                              need_decompress ? &decomp_strm : NULL, need_decompress,
                              error, error_len);
            if (cw == (size_t)-1) { if (decomp_init) inflateEnd(&decomp_strm); return -1; }
            if (chunk_state == 3) break;
        } else {
            size_t take = (size_t)n;
            if (body_remaining >= 0 && (long)take > body_remaining) take = (size_t)body_remaining;
            if (write_body_maybe_decomp(recv_buf, take, write_body ? body_out : NULL, out,
                                         need_decompress ? &decomp_strm : NULL, need_decompress,
                                         error, error_len) == (size_t)-1) {
                if (decomp_init) { inflateEnd(&decomp_strm); } return -1;
            }
            if (body_remaining >= 0) {
                body_remaining -= (long)take;
                if (body_remaining == 0) break;
            }
        }
    }

    out->preview[out->preview_len] = '\0';
    if (!seen_first_byte) out->ttfb_ms = -1.0;
    if (decomp_init) inflateEnd(&decomp_strm);
    return 0;
}
