#define _GNU_SOURCE
#include "http2_internal.h"

#include <stdlib.h>
#include <string.h>

/*
 * Handle a DATA frame: validate stream state, strip padding, write body,
 * update flow control, and detect end-of-stream with content-length check.
 * Returns 0 on success (caller frees payload), -1 on fatal (caller frees
 * payload and returns -1).
 */
static int handle_h2_data_frame(struct h2_connection *h2,
    struct h2_stream *s, struct h2_stream *dst,
    struct connection *conn, uint32_t fid, uint8_t flags,
    const char *payload, size_t length,
    const struct timespec *ttfb_start,
    char *error, size_t error_len)
{
    if (dst == NULL) return 0;
    if (dst->state != H2_SS_OPEN && dst->state != H2_SS_HALF_CLOSED_LOCAL) {
        send_rst_stream(conn, fid, H2_STREAM_CLOSED, error, error_len);
        return 0;
    }

    size_t data_off = 0;
    if (flags & H2_FLAG_PADDED) {
        if (length < 1) { set_error(error, error_len, "Truncated padded DATA"); return -1; }
        unsigned char pad_len = (unsigned char)payload[0];
        data_off = 1;
        if (data_off + pad_len > length) { set_error(error, error_len, "Invalid padding in DATA"); return -1; }
    }

    size_t data_len_actual = length - data_off;

    if (data_len_actual == 0 && !(flags & H2_FLAG_END_STREAM)) {
        send_rst_stream(conn, fid, H2_ENHANCE_YOUR_CALM, error, error_len);
        return 0;
    }

    if (dst == s && !s->seen_first_byte && data_len_actual > 0) {
        if (clock_gettime(CLOCK_MONOTONIC, &s->first_byte_ts) != 0) {
            set_error(error, error_len, "clock_gettime failed");
            return -1;
        }
        s->out->ttfb_ms = ms_between(ttfb_start, &s->first_byte_ts);
        s->seen_first_byte = true;
    }

    if (data_len_actual > 0) {
        const char *body_data = payload + data_off;
        if (dst == s && s->body_out != NULL &&
            fwrite(body_data, 1, data_len_actual, s->body_out) != data_len_actual) {
            set_error(error, error_len, "Failed to write response body");
            return -1;
        }
        if (dst == s && s->body_out == NULL) {
            if (s->out->body_len > MAX_BODY_BUF || data_len_actual > MAX_BODY_BUF - s->out->body_len) {
                set_error(error, error_len, "Response body too large");
                return -1;
            }
            size_t needed = s->out->body_len + data_len_actual;
            if (needed > s->out->body_cap) {
                size_t new_cap = s->out->body_cap ? s->out->body_cap : 4096;
                while (new_cap < needed) {
                    if (new_cap > MAX_BODY_BUF / 2) { new_cap = MAX_BODY_BUF; break; }
                    new_cap *= 2;
                }
                if (new_cap > MAX_BODY_BUF) new_cap = MAX_BODY_BUF;
                char *new_buf = realloc(s->out->body_buf, new_cap);
                if (new_buf == NULL) {
                    set_error(error, error_len, "Out of memory");
                    return -1;
                }
                s->out->body_buf = new_buf;
                s->out->body_cap = new_cap;
            }
            memcpy(s->out->body_buf + s->out->body_len, body_data, data_len_actual);
            s->out->body_len = needed;
        }

        dst->recv_data_len += data_len_actual;
        h2->conn_window_consumed += data_len_actual;
        dst->recv_window_consumed += data_len_actual;
        flush_window_updates(conn, h2, error, error_len);
        dst->trailers_pending = true;
    }

    if (flags & H2_FLAG_END_STREAM) {
        if (dst == s && s->out->content_length >= 0 &&
            s->recv_data_len != (uint64_t)s->out->content_length) {
            set_error(error, error_len,
                "HTTP/2 Content-Length mismatch: expected %lld bytes, got %llu",
                (long long)s->out->content_length,
                (unsigned long long)s->recv_data_len);
            return -1;
        }
        dst->done = true;
        dst->state = H2_SS_CLOSED;
        free_stream(h2, dst);
        flush_window_updates(conn, h2, error, error_len);
    }

    return 0;
}

int http2_receive_response(struct connection *conn, uint32_t stream_id,
                           struct response_info *out,
                           const struct timespec *ttfb_start,
                           FILE *body_out, char *error, size_t error_len) {
    struct h2_connection *h2 = conn->h2;
    struct h2_stream *s = stream_by_id(h2, stream_id);
    if (s == NULL) {
        set_error(error, error_len, "Unknown stream ID");
        return -1;
    }

    s->out = out;
    s->body_out = body_out;

    out->status_code = 0;
    out->content_length = -1;
    out->chunked = false;
    out->set_cookie_len = 0;
    out->set_cookie_buf[0] = '\0';
    out->content_encoding[0] = '\0';
    out->location[0] = '\0';
    out->ttfb_ms = -1.0;

    while (!s->done) {
        unsigned char header[H2_FRAME_HEADER_SIZE];
        if (conn_read(conn, (char *)header, sizeof(header), error, error_len) != 0)
            return -1;

        size_t length = read24(header);
        uint8_t type = header[3];
        uint8_t flags = header[4];
        uint32_t fid = (((uint32_t)(header[5] & 0x7F) << 24) |
                        ((uint32_t)header[6] << 16) |
                        ((uint32_t)header[7] << 8) |
                        (uint32_t)header[8]);

        if (length > h2->settings.max_frame_size) {
            set_error(error, error_len, "HTTP/2 frame exceeds max frame size");
            return -1;
        }

        char *payload = NULL;

        if (length > 0) {
            payload = malloc(length);
            if (payload == NULL) {
                set_error(error, error_len, "Out of memory");
                return -1;
            }
            if (conn_read(conn, payload, length, error, error_len) != 0) {
                free(payload);
                return -1;
            }
        }

        struct h2_stream *dst = stream_by_id(h2, fid);
        if (dst == NULL && type != H2_SETTINGS && type != H2_PING &&
            type != H2_GOAWAY && type != H2_PRIORITY && type != H2_WINDOW_UPDATE) {
            free(payload);
            continue;
        }

        if (type == H2_SETTINGS) {
            if (flags & H2_FLAG_SETTINGS_ACK) {
                if (length != 0) {
                    free(payload);
                    set_error(error, error_len,
                        "HTTP/2 SETTINGS ACK frame must have empty payload");
                    return -1;
                }
                free(payload);
                continue;
            }
            if (h2_settings_apply(h2, (const unsigned char *)payload, length,
                                  error, error_len) != 0) {
                free(payload);
                return -1;
            }
            send_settings_ack(conn, error, error_len);
            free(payload);
            continue;
        }

        if (type == H2_WINDOW_UPDATE) {
            if (length >= 4) {
                const unsigned char *p = (const unsigned char *)payload;
                uint32_t inc = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                               ((uint32_t)p[2] << 8) | p[3];
                if (inc >= (1u << 31)) {
                    free(payload);
                    set_error(error, error_len, "WINDOW_UPDATE increment too large");
                    return -1;
                }
                if (fid == 0) {
                    if ((int32_t)(0x7FFFFFFF - h2->conn_window) < (int32_t)inc) {
                        free(payload);
                        set_error(error, error_len, "WINDOW_UPDATE would overflow flow control window");
                        return -1;
                    }
                    h2->conn_window += (int32_t)inc;
                } else if (dst != NULL) {
                    if ((int32_t)(0x7FFFFFFF - dst->window) < (int32_t)inc) {
                        free(payload);
                        set_error(error, error_len, "WINDOW_UPDATE would overflow flow control window");
                        return -1;
                    }
                    dst->window += (int32_t)inc;
                }
            }
            free(payload);
            continue;
        }

        if (type == H2_PING) {
            if (length != 8) {
                free(payload);
                set_error(error, error_len,
                    "HTTP/2 PING frame payload must be 8 octets");
                return -1;
            }
            if (!(flags & 0x1))
                send_ping_ack(conn, payload, error, error_len);
            free(payload);
            continue;
        }

        if (type == H2_GOAWAY) {
            if (length < 8) {
                free(payload);
                set_error(error, error_len,
                    "HTTP/2 GOAWAY frame must have at least 8 octets");
                return -1;
            }
            h2->goaway_received = true;
            unsigned char *gp = (unsigned char *)payload;
            h2->goaway_last_stream_id = ((uint32_t)(gp[0] & 0x7F) << 24) |
                                         ((uint32_t)gp[1] << 16) |
                                         ((uint32_t)gp[2] << 8) |
                                         (uint32_t)gp[3];
            if (stream_id <= h2->goaway_last_stream_id) {
                h2->goaway_graceful = true;
                free(payload);
                continue;
            }
            free(payload);
            set_error(error, error_len, "HTTP/2 server sent GOAWAY with last-stream-id < our stream");
            return -1;
        }

        if (type == H2_RST_STREAM) {
            if (dst != NULL) {
                dst->state = H2_SS_CLOSED;
                dst->done = true;
                if (dst == s) {
                    free(payload);
                    set_error(error, error_len, "HTTP/2 stream was reset by server");
                    return -1;
                }
                free_stream(h2, dst);
                flush_window_updates(conn, h2, error, error_len);
            }
            free(payload);
            continue;
        }

        if (type == H2_PUSH_PROMISE) {
            send_rst_stream(conn, fid, H2_REFUSED_STREAM, error, error_len);
            if (length >= 4) {
                uint32_t promised_id = ((uint32_t)((unsigned char)payload[0] & 0x7F) << 24) |
                                        ((uint32_t)(unsigned char)payload[1] << 16) |
                                        ((uint32_t)(unsigned char)payload[2] << 8) |
                                        (unsigned char)payload[3];
                send_rst_stream(conn, promised_id, H2_REFUSED_STREAM, error, error_len);
            }
            free(payload);
            continue;
        }

        if (type == H2_PRIORITY) {
            if (length != 5) {
                free(payload);
                set_error(error, error_len, "PRIORITY frame must be exactly 5 bytes");
                return -1;
            }
            free(payload);
            continue;
        }

        if (type == H2_HEADERS || type == H2_CONTINUATION) {
            if (dst == NULL) {
                if (type == H2_HEADERS && (fid & 1) == 0) {
                    send_rst_stream(conn, fid, H2_REFUSED_STREAM, error, error_len);
                }
                free(payload);
                continue;
            }
            if (type == H2_HEADERS) {
                if (dst->continuation_pending) {
                    send_rst_stream(conn, fid, H2_PROTOCOL_ERROR, error, error_len);
                    free(payload);
                    continue;
                }
                if (dst->state == H2_SS_CLOSED) {
                    send_rst_stream(conn, fid, H2_STREAM_CLOSED, error, error_len);
                    free(payload);
                    continue;
                }
                if (dst->state == H2_SS_HALF_CLOSED_REMOTE) {
                    send_rst_stream(conn, fid, H2_STREAM_CLOSED, error, error_len);
                    free(payload);
                    continue;
                }
                if (dst->state == H2_SS_IDLE) {
                    dst->state = (flags & H2_FLAG_END_STREAM) ? H2_SS_HALF_CLOSED_REMOTE : H2_SS_OPEN;
                }
            } else if (!dst->continuation_pending) {
                send_rst_stream(conn, fid, H2_PROTOCOL_ERROR, error, error_len);
                free(payload);
                continue;
            }

            if (type == H2_HEADERS) {
                dst->header_list_size = 0;
                dst->trailers_pending = false;
                dst->saw_regular_header = false;
            }

            if (!(flags & H2_FLAG_END_HEADERS))
                dst->continuation_pending = true;
            else
                dst->continuation_pending = false;

            size_t hpack_off = 0;
            if (type == H2_HEADERS && (flags & H2_FLAG_PADDED)) {
                if (length < 1) { free(payload); set_error(error, error_len, "Truncated padded HEADERS"); return -1; }
                unsigned char pad_len = (unsigned char)payload[0];
                hpack_off = 1 + pad_len;
                if (hpack_off > length) { free(payload); set_error(error, error_len, "Invalid padding in HEADERS"); return -1; }
            }

            if (type == H2_HEADERS && (flags & H2_FLAG_PRIORITY)) {
                if (length < hpack_off + 5) { free(payload); set_error(error, error_len, "Truncated priority HEADERS"); return -1; }
                hpack_off += 5;
            }

            size_t hpack_len = length - hpack_off;

            if (dst == s && !s->seen_first_byte && hpack_len > 0) {
                if (clock_gettime(CLOCK_MONOTONIC, &s->first_byte_ts) != 0) {
                    free(payload);
                    set_error(error, error_len, "clock_gettime failed");
                    return -1;
                }
                s->out->ttfb_ms = ms_between(ttfb_start, &s->first_byte_ts);
                s->seen_first_byte = true;
            }

            int hp_ret = parse_h2_header_block(h2, dst, conn, fid,
                (const unsigned char *)payload + hpack_off, hpack_len,
                error, error_len);
            if (hp_ret < 0) goto hpack_error;
            if (hp_ret > 0) goto stream_reset;

            if (flags & H2_FLAG_END_STREAM) {
                dst->done = true;
                dst->state = H2_SS_CLOSED;
                free_stream(h2, dst);
                flush_window_updates(conn, h2, error, error_len);
            }

            free(payload);
            continue;

        stream_reset:
            free(payload);
            continue;
        }

        if (type == H2_DATA) {
            if (handle_h2_data_frame(h2, s, dst, conn, fid, flags, payload, length,
                                     ttfb_start, error, error_len) < 0) {
                free(payload);
                return -1;
            }
            free(payload);
            continue;
        }

        free(payload);
        continue;

    hpack_error:
        free(payload);
        send_goaway(conn, h2->last_stream_id, H2_COMPRESSION_ERROR,
                    error, error_len);
        set_error(error, error_len,
            "HTTP/2 HPACK decompression error");
        return -1;
    }

    if (!s->seen_first_byte) s->out->ttfb_ms = -1.0;
    return 0;
}
