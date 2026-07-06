#define _GNU_SOURCE
#include "curldbg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <zlib.h>

bool is_redirect_status(int status_code) {
    if (status_code == 301 || status_code == 302) return true;
    if (status_code == 303 || status_code == 307 || status_code == 308) return true;
    return false;
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
    {
        const char *sp = headers;
        while (*sp && *sp != ' ') sp++;
        if (*sp == ' ') {
            sp++;
            int code = 0;
            while (*sp >= '0' && *sp <= '9')
                code = code * 10 + (*sp++ - '0');
            if (code >= 100 && code <= 599)
                out->status_code = code;
            else { out->status_code = 0; return; }
        } else { out->status_code = 0; return; }
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
            char c = (char)(line[0] | 32);
            if (c == 'l' && line[1] == 'o' && strncasecmp(line + 2, "cation:", 7) == 0) {
                char *value = line + 9;
                trim_spaces(&value);
                strncpy(out->location, value, sizeof(out->location) - 1);
                out->location[sizeof(out->location) - 1] = '\0';
            } else if (c == 'c') {
                if (line_len >= 17 && line[1] == 'o' &&
                    strncasecmp(line + 2, "ntent-Encoding:", 15) == 0) {
                    const char *val = line + 17;
                    trim_spaces((char **)&val);
                    strncpy(out->content_encoding, val, sizeof(out->content_encoding) - 1);
                    out->content_encoding[sizeof(out->content_encoding) - 1] = '\0';
                } else if (line_len >= 15 && line[1] == 'o' &&
                           strncasecmp(line + 2, "ntent-Length:", 13) == 0) {
                    const char *val = line + 15;
                    trim_spaces((char **)&val);
                    char *end = NULL;
                    long cl = strtol(val, &end, 10);
                    if (*end == '\0' && cl >= 0) out->content_length = cl;
                }
            } else if (c == 't' && line_len >= 18 && line[1] == 'r' &&
                       strncasecmp(line + 2, "ansfer-Encoding:", 16) == 0) {
                const char *val = line + 18;
                trim_spaces((char **)&val);
                if (strcasecmp(val, "chunked") == 0) out->chunked = true;
            } else if (c == 's' && line_len >= 12 && line[1] == 'e' &&
                       strncasecmp(line + 2, "t-Cookie:", 9) == 0) {
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

    static __thread char recv_buf[RECV_BUF_SIZE]
        __attribute__((aligned(64)));
    static __thread char pending_body_buf[RECV_BUF_SIZE]
        __attribute__((aligned(64)));
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

    out->preview_len = 0;
    out->ttfb_ms = -1.0;
    out->status_code = 0;
    out->location[0] = '\0';
    out->chunked = false;
    out->content_length = -1;
    out->set_cookie_len = 0;
    out->set_cookie_buf[0] = '\0';
    out->content_encoding[0] = '\0';

    for (;;) {
        ssize_t n;

        if (__builtin_expect(!header_done, 0)) {
            n = connection_read(conn, recv_buf + header_len,
                                sizeof(recv_buf) - header_len,
                                error, error_len);
        } else {
            n = connection_read(conn, recv_buf, sizeof(recv_buf), error, error_len);
        }
        if (n < 0) return -1;
        if (n == 0) break;

        if (__builtin_expect(!seen_first_byte, 0)) {
            if (clock_gettime(CLOCK_MONOTONIC, &first_byte_ts) != 0) {
                set_error(error, error_len, "clock_gettime failed"); return -1;
            }
            out->ttfb_ms = ms_between(ttfb_start, &first_byte_ts);
            seen_first_byte = true;
        }

        if (__builtin_expect(!header_done, 0)) {
            header_len += (size_t)n;
            if (header_len >= RECV_BUF_SIZE) {
                header_len = RECV_BUF_SIZE - 1;
                recv_buf[header_len] = '\0';
            }
            recv_buf[header_len] = '\0';

            char *body_start = find_header_end(recv_buf, header_len);
            if (body_start != NULL) {
                size_t header_bytes = (size_t)(body_start - recv_buf);
                size_t pending_len = header_len - header_bytes;

                if (pending_len > 0) {
                    memcpy(pending_body_buf, body_start, pending_len);
                }

                if (conn->verbose) {
                    char *headers_only = malloc(header_bytes + 1);
                    if (headers_only != NULL) {
                        memcpy(headers_only, recv_buf, header_bytes);
                        headers_only[header_bytes] = '\0';
                        char *line = headers_only;
                        while (*line != '\0') {
                            char *nl = strstr(line, "\r\n");
                            if (nl == NULL) break;
                            *nl = '\0';
                            fprintf(stderr, "< %s\n", line);
                            line = nl + 2;
                        }
                        free(headers_only);
                    }
                }

                recv_buf[header_bytes] = '\0';
                parse_response_headers(recv_buf, out);

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
                if (__builtin_expect(chunked, 0)) {
                    size_t cw = chunked_write(pending_body_buf, pending_len, write_body ? body_out : NULL, out,
                                      &chunk_state, &chunk_remaining, chunk_line_buf, &chunk_line_len,
                                      need_decompress ? &decomp_strm : NULL, need_decompress,
                                      error, error_len);
                    if (cw == (size_t)-1) { if (decomp_init) inflateEnd(&decomp_strm); return -1; }
                    if (chunk_state == 3 && cw < pending_len) {
                        size_t off = cw;
                        while (off < pending_len) {
                            const char *cr = memchr(pending_body_buf + off, '\r', pending_len - off);
                            if (cr == NULL) break;
                            size_t cr_off = (size_t)(cr - pending_body_buf);
                            if (cr_off + 1 < pending_len && pending_body_buf[cr_off + 1] == '\n') {
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
                    if (write_body_maybe_decomp(pending_body_buf, pending_len, write_body ? body_out : NULL, out,
                                                 need_decompress ? &decomp_strm : NULL, need_decompress,
                                                 error, error_len) == (size_t)-1) {
                        if (decomp_init) { inflateEnd(&decomp_strm); } return -1;
                    }
                    if (body_remaining > 0) body_remaining -= (long)pending_len;
                }
                header_done = true;
                if (!chunked && body_remaining <= 0) break;
            } else if (header_len >= RECV_BUF_SIZE - 1) {
                set_error(error, error_len, "Response headers too large"); return -1;
            }
            continue;
        }

        if (__builtin_expect(chunked, 0)) {
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
