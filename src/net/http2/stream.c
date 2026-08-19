#define _GNU_SOURCE
#include "http2_internal.h"

#include <string.h>

struct h2_stream *stream_by_id(struct h2_connection *h2, uint32_t id) {
    for (size_t i = 0; i < H2_MAX_STREAMS; i++) {
        if (h2->streams[i].active && h2->streams[i].id == id)
            return &h2->streams[i];
    }
    return NULL;
}

struct h2_stream *alloc_stream(struct h2_connection *h2) {
    for (size_t i = 0; i < H2_MAX_STREAMS; i++) {
        if (!h2->streams[i].active) {
            memset(&h2->streams[i], 0, sizeof(struct h2_stream));
            h2->streams[i].active = true;
            h2->active_stream_count++;
            return &h2->streams[i];
        }
    }
    return NULL;
}

void free_stream(struct h2_connection *h2, struct h2_stream *s) {
    s->active = false;
    s->done = true;
    if (h2->active_stream_count > 0) h2->active_stream_count--;
}

void flush_window_updates(struct connection *conn, struct h2_connection *h2,
                          char *error, size_t error_len) {
    if (h2->conn_window_consumed >= H2_WINDOW_UPDATE_THRESHOLD) {
        send_window_update(conn, 0, (uint32_t)h2->conn_window_consumed, error, error_len);
        h2->conn_window_consumed = 0;
    }
    for (size_t i = 0; i < H2_MAX_STREAMS; i++) {
        struct h2_stream *s = &h2->streams[i];
        if (s->active && s->recv_window_consumed >= H2_WINDOW_UPDATE_THRESHOLD) {
            send_window_update(conn, s->id, (uint32_t)s->recv_window_consumed, error, error_len);
            s->recv_window_consumed = 0;
        }
    }
}
