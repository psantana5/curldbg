#define _GNU_SOURCE
#include "http2_internal.h"

#include <stdlib.h>
#include <string.h>

uint32_t http2_send_request(struct connection *conn, const struct url_info *url,
                            const char *method, const char *data, size_t data_len,
                            const char **extra_headers, size_t extra_header_count,
                            const char *user_agent, const char *basic_auth,
                            char *error, size_t error_len) {
    struct h2_connection *h2 = conn->h2;
    (void)error;
    (void)error_len;
    if (user_agent == NULL) user_agent = "curldbg/" CURLDBG_VERSION;

    if (h2->goaway_received) {
        if (!h2->goaway_graceful) {
            set_error(error, error_len, "Cannot send request after GOAWAY");
            return 0;
        }
        if (h2->last_stream_id + 2 > h2->goaway_last_stream_id) {
            set_error(error, error_len,
                "Cannot send request: stream ID would exceed GOAWAY last_stream_id");
            return 0;
        }
    }

    if (h2->active_stream_count >= h2->settings.max_concurrent_streams) {
        set_error(error, error_len, "Max concurrent streams reached");
        return 0;
    }

    struct h2_stream *s = alloc_stream(h2);
    if (s == NULL) {
        set_error(error, error_len, "No available stream slots");
        return 0;
    }

    h2->last_stream_id += 2;
    s->id = h2->last_stream_id;
    s->state = H2_SS_IDLE;
    s->window = (int32_t)h2->settings.initial_window_size;

    uint32_t stream_id = s->id;
    const char *scheme = url->use_tls ? "https" : "http";
    char host_header[320];
    if (format_host_header(url, host_header, sizeof(host_header)) != 0) {
        free_stream(h2, s);
        set_error(error, error_len, "Host header too large");
        return 0;
    }

    bool is_connect = (strcmp(method, "CONNECT") == 0);

    struct auto_buf ab;
    auto_buf_init(&ab, 65536);
    if (ab.data == NULL) {
        set_error(error, error_len, "Out of memory");
        free_stream(h2, s);
        return 0;
    }
    unsigned char *block = (unsigned char *)ab.data;
    size_t block_cap = 65536;
    size_t block_len = 0;
    int n;

#define H2_REQ_FAIL(msg) do { auto_buf_done(&ab); set_error(error, error_len, msg); free_stream(h2, s); return 0; } while(0)

    n = hpack_encode_literal_with_indexing(block, block_cap, 0,
                                            ":method", 7, method, strlen(method));
    if (n < 0) { H2_REQ_FAIL("HPACK encode failed"); }
    block_len = (size_t)n;

    if (!is_connect) {
        n = hpack_encode_literal_with_indexing(block + block_len, block_cap - block_len, 0,
                                                ":scheme", 7, scheme, strlen(scheme));
        if (n < 0) { H2_REQ_FAIL("HPACK encode failed"); }
        block_len += (size_t)n;
    }

    n = hpack_encode_literal_with_indexing(block + block_len, block_cap - block_len, 0,
                                            ":authority", 10, host_header, strlen(host_header));
    if (n < 0) { H2_REQ_FAIL("HPACK encode failed"); }
    block_len += (size_t)n;

    if (!is_connect) {
        n = hpack_encode_literal_without_indexing(block + block_len, block_cap - block_len, 0,
                                                   ":path", 5, url->path, strlen(url->path));
        if (n < 0) { H2_REQ_FAIL("HPACK encode failed"); }
        block_len += (size_t)n;
    }

    n = hpack_encode_literal_without_indexing(block + block_len, block_cap - block_len, 0,
                                               "user-agent", 10, user_agent, strlen(user_agent));
    if (n < 0) { H2_REQ_FAIL("HPACK encode failed"); }
    block_len += (size_t)n;

    if (basic_auth != NULL && basic_auth[0] != '\0') {
        char auth_b64[512];
        char auth_header[1024];
        if (base64_encode((const unsigned char *)basic_auth, strlen(basic_auth),
                           auth_b64, sizeof(auth_b64)) != 0) {
            H2_REQ_FAIL("Basic auth value too large");
        }
        int na = snprintf(auth_header, sizeof(auth_header), "Basic %s", auth_b64);
        if (na < 0 || (size_t)na >= sizeof(auth_header)) {
            H2_REQ_FAIL("Authorization header too large");
        }
        n = hpack_encode_literal_without_indexing(block + block_len, block_cap - block_len,
                                                   0, "authorization", 13,
                                                   auth_header, (size_t)na);
        if (n < 0) { H2_REQ_FAIL("HPACK encode failed"); }
        block_len += (size_t)n;
    }

    for (size_t i = 0; i < extra_header_count; i++) {
        if (extra_headers[i] == NULL) continue;
        const char *colon = strchr(extra_headers[i], ':');
        if (colon == NULL) continue;
        size_t name_len = (size_t)(colon - extra_headers[i]);
        const char *val = colon + 1;
        while (*val == ' ' || *val == '\t') val++;
        size_t val_len = strlen(val);

        char lc_name[256];
        size_t lc_len = name_len;
        if (lc_len >= sizeof(lc_name)) lc_len = sizeof(lc_name) - 1;
        for (size_t j = 0; j < lc_len; j++)
            lc_name[j] = (char)(extra_headers[i][j] | 32);
        lc_name[lc_len] = '\0';

        if (strcmp(lc_name, "connection") == 0 ||
            strcmp(lc_name, "keep-alive") == 0 ||
            strcmp(lc_name, "proxy-connection") == 0 ||
            strcmp(lc_name, "transfer-encoding") == 0 ||
            strcmp(lc_name, "upgrade") == 0)
            continue;
        if (strcmp(lc_name, "te") == 0) {
            if (strcmp(val, "trailers") != 0)
                continue;
        }

        int name_idx = 0;
        lookup_static_name(lc_name, lc_len, &name_idx);

        n = hpack_encode_literal_without_indexing(block + block_len, block_cap - block_len,
                                                   (uint64_t)name_idx,
                                                   lc_name, lc_len, val, val_len);
        if (n < 0) { H2_REQ_FAIL("HPACK encode failed"); }
        block_len += (size_t)n;
    }

    if (conn->verbose) {
        fprintf(stderr, "* Using HTTP/2 (stream %u)\n", stream_id);
        fprintf(stderr, "* Sending %zu bytes of HPACK-encoded headers\n", block_len);
    }

    bool end_stream = (data == NULL || data_len == 0);
    uint8_t flags = H2_FLAG_END_HEADERS | (end_stream ? H2_FLAG_END_STREAM : 0);

    size_t max_payload = h2->settings.max_frame_size;
    if (block_len <= max_payload) {
        if (send_frame_raw(conn, block_len, H2_HEADERS, flags, stream_id,
                           (char *)block, error, error_len) != 0)
            { auto_buf_done(&ab); free_stream(h2, s); return 0; }
    } else {
        size_t off = 0;
        size_t chunk = max_payload;
        bool first = true;
        while (off < block_len) {
            if (off + chunk > block_len)
                chunk = block_len - off;
            uint8_t ftype = first ? H2_HEADERS : H2_CONTINUATION;
            uint8_t fflags = (off + chunk >= block_len) ? H2_FLAG_END_HEADERS : 0;
            if (send_frame_raw(conn, chunk, ftype, fflags, stream_id,
                               (char *)block + off, error, error_len) != 0)
                { auto_buf_done(&ab); free_stream(h2, s); return 0; }
            off += chunk;
            first = false;
        }
    }

    s->state = end_stream ? H2_SS_HALF_CLOSED_LOCAL : H2_SS_OPEN;

    if (data != NULL && data_len > 0) {
        size_t remaining = data_len;
        const char *ptr = data;
        while (remaining > 0) {
            size_t chunk = remaining;
            if (chunk > h2->settings.max_frame_size)
                chunk = h2->settings.max_frame_size;
            if ((int32_t)chunk > s->window)
                chunk = (size_t)s->window;
            if ((int32_t)chunk > h2->conn_window)
                chunk = (size_t)h2->conn_window;
            if (chunk == 0) {
                unsigned char whdr[H2_FRAME_HEADER_SIZE];
                int pollret = conn_readable(conn, 10000);
                if (pollret <= 0) {
                    set_error(error, error_len, pollret == 0
                              ? "HTTP/2 send timed out waiting for WINDOW_UPDATE"
                              : "HTTP/2 poll failed while draining window");
                    auto_buf_done(&ab); free_stream(h2, s); return 0;
                }
                if (conn_read(conn, (char *)whdr, sizeof(whdr), error, error_len) != 0)
                    { auto_buf_done(&ab); free_stream(h2, s); return 0; }
                size_t wlen = read24(whdr);
                uint8_t wtype = whdr[3];
                uint32_t wfid = (((uint32_t)(whdr[5] & 0x7F) << 24) |
                                 ((uint32_t)whdr[6] << 16) |
                                 ((uint32_t)whdr[7] << 8) |
                                 (uint32_t)whdr[8]);
                if (wtype == H2_WINDOW_UPDATE && wlen >= 4) {
                    char wpayload[4];
                    if (conn_read(conn, wpayload, 4, error, error_len) != 0)
                        { auto_buf_done(&ab); free_stream(h2, s); return 0; }
                    uint32_t inc = (uint32_t)((unsigned char)wpayload[0] << 24) |
                                   (uint32_t)((unsigned char)wpayload[1] << 16) |
                                   (uint32_t)((unsigned char)wpayload[2] << 8) |
                                   (unsigned char)wpayload[3];
                    if (inc < (1u << 31)) {
                        if (wfid == 0) {
                            if ((int32_t)(0x7FFFFFFF - h2->conn_window) < (int32_t)inc) {
                                auto_buf_done(&ab); free_stream(h2, s); return 0;
                            }
                            h2->conn_window += (int32_t)inc;
                        } else if (wfid == stream_id) {
                            if ((int32_t)(0x7FFFFFFF - s->window) < (int32_t)inc) {
                                auto_buf_done(&ab); free_stream(h2, s); return 0;
                            }
                            s->window += (int32_t)inc;
                        }
                    }
                } else {
                    if (wtype == H2_GOAWAY) {
                        h2->goaway_received = true;
                        if (wlen >= 8) {
                            char wpayload[8];
                            if (conn_read(conn, wpayload, 8, error, error_len) != 0)
                                { auto_buf_done(&ab); free_stream(h2, s); return 0; }
                            uint32_t last_id = ((uint32_t)((unsigned char)wpayload[0] & 0x7F) << 24) |
                                                ((uint32_t)(unsigned char)wpayload[1] << 16) |
                                                ((uint32_t)(unsigned char)wpayload[2] << 8) |
                                                (unsigned char)wpayload[3];
                            h2->goaway_last_stream_id = last_id;
                            size_t remain = wlen - 8;
                            if (remain > 0) {
                                char *skip = malloc(remain);
                                if (skip) { conn_read(conn, skip, remain, error, error_len); free(skip); }
                            }
                            if (stream_id <= last_id)
                                continue;
                        }
                        set_error(error, error_len, "HTTP/2 server sent GOAWAY while sending body");
                        auto_buf_done(&ab); free_stream(h2, s); return 0;
                    }
                    if (wtype == H2_RST_STREAM && wfid == stream_id) {
                        if (wlen > 0) {
                            char *skip = malloc(wlen);
                            if (skip) { conn_read(conn, skip, wlen, error, error_len); free(skip); }
                        }
                        set_error(error, error_len, "HTTP/2 stream reset while sending body");
                        auto_buf_done(&ab); free_stream(h2, s); return 0;
                    }
                    if (wtype == H2_SETTINGS) {
                        if (wlen > 0) {
                            char *wp = malloc(wlen);
                            if (wp) {
                                conn_read(conn, wp, wlen, error, error_len);
                                if (h2_settings_apply(h2, (const unsigned char *)wp, wlen,
                                                      error, error_len) != 0) {
                                    free(wp);
                                    auto_buf_done(&ab);
                                    free_stream(h2, s);
                                    return 0;
                                }
                                free(wp);
                            }
                        }
                        send_settings_ack(conn, error, error_len);
                        continue;
                    }
                    if (wtype == H2_PING && (whdr[4] & 0x1) == 0) {
                        if (wlen >= 8) {
                            char pp[8];
                            conn_read(conn, pp, 8, error, error_len);
                            send_ping_ack(conn, pp, error, error_len);
                            wlen -= 8;
                        }
                        if (wlen > 0) {
                            char *skip = malloc(wlen);
                            if (skip) { conn_read(conn, skip, wlen, error, error_len); free(skip); }
                        }
                        continue;
                    }
                    if (wlen > 0) {
                        char *skip = malloc(wlen);
                        if (skip) {
                            conn_read(conn, skip, wlen, error, error_len);
                            free(skip);
                        }
                    }
                }
                continue;
            }
            uint8_t data_flags = (remaining == chunk) ? H2_FLAG_END_STREAM : 0;
            if (send_frame_raw(conn, chunk, H2_DATA, data_flags,
                               stream_id, ptr, error, error_len) != 0)
                { auto_buf_done(&ab); free_stream(h2, s); return 0; }
            h2->conn_window -= (int32_t)chunk;
            s->window -= (int32_t)chunk;
            remaining -= chunk;
            ptr += chunk;
        }
        s->state = H2_SS_HALF_CLOSED_LOCAL;
    }

    auto_buf_done(&ab);
    return stream_id;
}

#undef H2_REQ_FAIL
