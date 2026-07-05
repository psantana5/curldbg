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

        if (line_len >= 9 && strncasecmp(line, "Location:", 9) == 0) {
            char *value = line + 9;
            trim_spaces(&value);
            strncpy(out->location, value, sizeof(out->location) - 1);
            out->location[sizeof(out->location) - 1] = '\0';
        } else if (line_len >= 15 && strncasecmp(line, "Content-Length:", 15) == 0) {
            const char *val = line + 15;
            trim_spaces((char **)&val);
            char *end = NULL;
            long cl = strtol(val, &end, 10);
            if (*end == '\0' && cl >= 0) out->content_length = cl;
        } else if (line_len >= 18 && strncasecmp(line, "Transfer-Encoding:", 18) == 0) {
            const char *val = line + 18;
            trim_spaces((char **)&val);
            if (strcasecmp(val, "chunked") == 0) out->chunked = true;
        } else if (line_len >= 16 && strncasecmp(line, "Content-Encoding:", 16) == 0) {
            const char *val = line + 16;
            trim_spaces((char **)&val);
            strncpy(out->content_encoding, val, sizeof(out->content_encoding) - 1);
            out->content_encoding[sizeof(out->content_encoding) - 1] = '\0';
        } else if (line_len >= 12 && strncasecmp(line, "Set-Cookie:", 11) == 0) {
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

        line = nl + 1;
        remaining = HEADER_MAX - (size_t)(line - headers);
    }
}

static char *find_header_end(char *buf, size_t len) {
    if (len < 4) return NULL;
    for (size_t i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
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

static int build_request_buffer(const char *verb, const char *request_target,
                                 const char *host_header, const char *user_agent,
                                 const char *body_headers, bool include_body_headers,
                                 const char *auth_header, size_t auth_len,
                                 const char **extra_headers, size_t extra_header_count,
                                 bool has_host, bool compressed, bool has_accept_encoding,
                                 bool has_user_agent,
                                 char *req, size_t req_size,
                                 char *error, size_t error_len) {
    size_t offset = 0;
    if (append_str(req, req_size, &offset, verb) != 0) {
        set_error(error, error_len, "Request is too large"); return -1;
    }
    req[offset++] = ' ';
    if (append_str(req, req_size, &offset, request_target) != 0) {
        set_error(error, error_len, "Request is too large"); return -1;
    }
    if (append_str(req, req_size, &offset, " HTTP/1.1\r\n") != 0) {
        set_error(error, error_len, "Request is too large"); return -1;
    }
    if (!has_host) {
        if (append_str(req, req_size, &offset, "Host: ") != 0 ||
            append_str(req, req_size, &offset, host_header) != 0 ||
            append_str(req, req_size, &offset, "\r\n") != 0) {
            set_error(error, error_len, "Request is too large"); return -1;
        }
    }
    if (!has_user_agent) {
        if (append_str(req, req_size, &offset, "User-Agent: ") != 0 ||
            append_str(req, req_size, &offset, user_agent) != 0 ||
            append_str(req, req_size, &offset, "\r\n") != 0) {
            set_error(error, error_len, "Request is too large"); return -1;
        }
    }

    if (compressed && !has_accept_encoding) {
        if (append_str(req, req_size, &offset, "Accept-Encoding: gzip, deflate\r\n") != 0) {
            set_error(error, error_len, "Request is too large"); return -1;
        }
    }

    if (include_body_headers && body_headers[0] != '\0') {
        if (append_str(req, req_size, &offset, body_headers) != 0) {
            set_error(error, error_len, "Request is too large"); return -1;
        }
    }
    if (auth_len > 0) {
        if (append_str(req, req_size, &offset, auth_header) != 0) {
            set_error(error, error_len, "Request is too large"); return -1;
        }
    }
    for (size_t i = 0; i < extra_header_count; i++) {
        if (extra_headers[i] == NULL) continue;
        if (append_str(req, req_size, &offset, extra_headers[i]) != 0 ||
            append_str(req, req_size, &offset, "\r\n") != 0) {
            set_error(error, error_len, "Request is too large"); return -1;
        }
    }
    if (append_str(req, req_size, &offset, "\r\n") != 0) {
        set_error(error, error_len, "Request is too large"); return -1;
    }
    return 0;
}

static int write_upload_body(struct connection *conn, FILE *upload_file,
                              bool chunked_upload, char *error, size_t error_len) {
    char buf[4096];
    for (;;) {
        size_t nread = fread(buf, 1, sizeof(buf), upload_file);
        if (nread > 0) {
            if (chunked_upload) {
                char chunk_hdr[32];
                int hn = snprintf(chunk_hdr, sizeof(chunk_hdr), "%zx\r\n", nread);
                if (connection_write_all(conn, chunk_hdr, (size_t)hn, error, error_len) != 0) return -1;
            }
            if (connection_write_all(conn, buf, nread, error, error_len) != 0) return -1;
            if (chunked_upload) {
                if (connection_write_all(conn, "\r\n", 2, error, error_len) != 0) return -1;
            }
        }
        if (nread < sizeof(buf)) {
            if (ferror(upload_file)) { set_error(error, error_len, "Failed to read upload file"); return -1; }
            break;
        }
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
    size_t extra_len = 0, auth_len = 0, content_len = 0, req_len;
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

    if (basic_auth != NULL && basic_auth[0] != '\0') {
        if (base64_encode((const unsigned char *)basic_auth, strlen(basic_auth), auth_b64, sizeof(auth_b64)) != 0) {
            set_error(error, error_len, "Basic auth value is too large"); return -1;
        }
        n = snprintf(auth_header, sizeof(auth_header), "Authorization: Basic %s\r\n", auth_b64);
        if (n < 0 || (size_t)n >= sizeof(auth_header)) {
            set_error(error, error_len, "Authorization header is too large"); return -1;
        }
        auth_len = (size_t)n;
    }

    for (size_t i = 0; i < extra_header_count; i++) {
        if (extra_headers[i] != NULL) extra_len += strlen(extra_headers[i]) + 2;
    }

    req_len = strlen(verb) + strlen(url->path) + strlen(host_header) +
              strlen(body_headers) + auth_len + extra_len + 128;
    char *req = malloc(req_len + 1);
    if (req == NULL) { set_error(error, error_len, "Out of memory building request"); return -1; }

    char proxy_abs_uri[2048];
    const char *request_target;
    if (use_proxy) {
        format_absolute_uri(url, proxy_abs_uri, sizeof(proxy_abs_uri));
        request_target = proxy_abs_uri;
    } else {
        request_target = url->path;
    }

    if (build_request_buffer(verb, request_target, host_header, user_agent,
                             body_headers, include_body_headers,
                             auth_header, auth_len,
                             extra_headers, extra_header_count,
                             has_host, compressed, has_accept_encoding,
                             has_user_agent,
                             req, req_len + 1, error, error_len) != 0) {
        free(req); return -1;
    }

    if (conn->verbose) {
        fprintf(stderr, "> %s %s HTTP/1.1\n", verb, request_target);
        if (!has_host) fprintf(stderr, "> Host: %s\n", host_header);
        if (!has_user_agent) fprintf(stderr, "> User-Agent: %s\n", user_agent);
        if (include_body_headers) {
            size_t off = 0;
            while (off < strlen(body_headers)) {
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

    if (connection_write_all(conn, req, strlen(req), error, error_len) != 0) { free(req); return -1; }
    free(req);

    if (data_len > 0) return connection_write_all(conn, data, data_len, error, error_len);

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

        if (trailer_mode) {
            size_t off = 0;
            while (off < (size_t)n) {
                const char *cr = memchr(recv_buf + off, '\r', (size_t)n - off);
                if (cr == NULL) break;
                size_t cr_off = (size_t)(cr - recv_buf);
                if (cr_off + 1 < (size_t)n && recv_buf[cr_off + 1] == '\n') {
                    bool empty = (cr_off == off);
                    off = cr_off + 2;
                    if (empty) { trailer_mode = false; break; }
                } else if (cr_off + 1 >= (size_t)n) {
                    break;
                } else {
                    off = cr_off + 1;
                }
            }
            if (!trailer_mode) continue;
            continue;
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

                char headers_only[HEADER_MAX + 1];
                memcpy(headers_only, header_buf, header_bytes);
                headers_only[header_bytes] = '\0';

                if (conn->verbose) {
                    char *line = headers_only;
                    while (*line != '\0') {
                        char *nl = strstr(line, "\r\n");
                        if (nl == NULL) break;
                        *nl = '\0';
                        fprintf(stderr, "< %s\n", line);
                        line = nl + 2;
                    }
                    memcpy(headers_only, header_buf, header_bytes);
                    headers_only[header_bytes] = '\0';
                }

                parse_response_headers(headers_only, out);

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
            size_t cw = chunked_write(recv_buf, (size_t)n, write_body ? body_out : NULL, out,
                              &chunk_state, &chunk_remaining, chunk_line_buf, &chunk_line_len,
                              need_decompress ? &decomp_strm : NULL, need_decompress,
                              error, error_len);
            if (cw == (size_t)-1) { if (decomp_init) inflateEnd(&decomp_strm); return -1; }
            if (chunk_state == 3 && cw < (size_t)n) break;
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
