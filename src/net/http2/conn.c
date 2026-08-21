#define _GNU_SOURCE
#include "http2_internal.h"

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>

int conn_write(struct connection *conn, const char *buf, size_t len,
               char *error, size_t error_len) {
    if (connection_write_all(conn, buf, len, error, error_len) != 0)
        return -1;
    return 0;
}

int conn_readable(struct connection *conn, int timeout_ms) {
    if (conn->ssl != NULL) {
        if (SSL_has_pending(conn->ssl))
            return 1;
        unsigned char c;
        int n = SSL_peek(conn->ssl, &c, 1);
        if (n > 0) return 1;
        if (n < 0) {
            int e = SSL_get_error(conn->ssl, n);
            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
                return 1;
        }
    }
    struct pollfd pfd = { .fd = conn->fd, .events = POLLIN };
    int ret;
    do {
        ret = poll(&pfd, 1, timeout_ms);
    } while (ret < 0 && errno == EINTR);
    return ret;
}

int conn_read(struct connection *conn, char *buf, size_t len,
              char *error, size_t error_len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = connection_read(conn, buf + off, len - off, error, error_len);
        if (n < 0) return -1;
        if (n == 0) {
            conn->last_errno = ECONNRESET;
            set_error(error, error_len, "HTTP/2 connection closed unexpectedly");
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

bool http2_negotiated(const struct connection *conn) {
    return conn != NULL && conn->http2;
}

int http2_init_connection(struct connection *conn, char *error, size_t error_len) {
    struct h2_connection *h2 = calloc(1, sizeof(struct h2_connection));
    if (h2 == NULL) {
        set_error(error, error_len, "Out of memory");
        return -1;
    }
    conn->h2 = h2;

    h2->streams = calloc(H2_MAX_STREAMS, sizeof(struct h2_stream));
    if (h2->streams == NULL) {
        conn->h2 = NULL;
        free(h2);
        set_error(error, error_len, "Out of memory");
        return -1;
    }

    h2->conn_window = H2_RFC_INITIAL_WINDOW;
    h2->settings.max_frame_size = H2_DEFAULT_MAX_FRAME_SIZE;
    h2->settings.initial_window_size = H2_RFC_INITIAL_WINDOW;
    h2->settings.header_table_size = H2_MAX_DYNAMIC_TABLE_SIZE;
    h2->last_stream_id = (uint32_t)-1;
    h2->settings.max_concurrent_streams = 100;
    h2->settings.enable_push = false;

    h2->dyn_table.max_size = H2_MAX_DYNAMIC_TABLE_SIZE;
    h2->dyn_table.capacity = 16;
    h2->dyn_table.entries = calloc(h2->dyn_table.capacity, sizeof(struct h2_hpack_entry));
    if (h2->dyn_table.entries == NULL) {
        set_error(error, error_len, "Out of memory");
        return -1;
    }

    if (huff_tree_init(&h2->huff_tree, NULL) != 0) {
        set_error(error, error_len, "Out of memory");
        return -1;
    }

    if (conn_write(conn, H2_CLIENT_PREFACE, strlen(H2_CLIENT_PREFACE),
                   error, error_len) != 0)
        return -1;

    if (send_client_settings(conn, error, error_len) != 0)
        return -1;

    bool got_settings = false;
    bool acked_our_settings = false;
    long long deadline = now_ms_monotonic() + 5000;

    while (!got_settings || !acked_our_settings) {
        long long now = now_ms_monotonic();
        if (now >= deadline) {
            set_error(error, error_len, "HTTP/2 connection preface timed out");
            return -1;
        }
        unsigned char header[H2_FRAME_HEADER_SIZE];
        int pollret = conn_readable(conn, (int)(deadline - now));
        if (pollret == 0) {
            set_error(error, error_len, "HTTP/2 connection preface timed out");
            return -1;
        }
        if (pollret < 0) {
            set_error(error, error_len, "HTTP/2 connection preface poll failed");
            return -1;
        }
        if (conn_read(conn, (char *)header, sizeof(header), error, error_len) != 0)
            return -1;

        size_t length = read24(header);
        uint8_t type = header[3];
        uint8_t flags = header[4];

        if (length > h2->settings.max_frame_size) {
            set_error(error, error_len, "HTTP/2 frame too large in init");
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

        if (type == H2_SETTINGS && !(flags & H2_FLAG_SETTINGS_ACK)) {
            got_settings = true;
            if (h2_settings_apply(h2, (const unsigned char *)payload, length,
                                  error, error_len) != 0) {
                free(payload);
                return -1;
            }
            if (send_settings_ack(conn, error, error_len) != 0) {
                free(payload);
                return -1;
            }
            h2->settings_received = true;
        } else if (type == H2_SETTINGS && (flags & H2_FLAG_SETTINGS_ACK)) {
            if (length != 0) {
                free(payload);
                set_error(error, error_len,
                    "HTTP/2 SETTINGS ACK frame must have empty payload");
                return -1;
            }
            acked_our_settings = true;
        } else if (type == H2_WINDOW_UPDATE && length >= 4) {
            uint32_t inc = (uint32_t)((unsigned char)payload[0] << 24) |
                          (uint32_t)((unsigned char)payload[1] << 16) |
                          (uint32_t)((unsigned char)payload[2] << 8) |
                          (unsigned char)payload[3];
            if (inc >= (1u << 31)) {
                free(payload);
                set_error(error, error_len, "WINDOW_UPDATE increment too large");
                return -1;
            }
            if ((int32_t)(0x7FFFFFFF - h2->conn_window) < (int32_t)inc) {
                free(payload);
                set_error(error, error_len, "WINDOW_UPDATE would overflow flow control window");
                return -1;
            }
            h2->conn_window += (int32_t)inc;
        } else if (type == H2_PING && !(flags & 0x1)) {
            if (length != 8) {
                free(payload);
                set_error(error, error_len,
                    "HTTP/2 PING frame payload must be 8 octets");
                return -1;
            }
            send_ping_ack(conn, payload, error, error_len);
        }

        free(payload);
    }

    /* Raise our receiving connection window from the RFC default (65535)
       to our target (1048576) so the server can send data without waiting
       for an immediate WINDOW_UPDATE. Stream windows are raised by the
       INITIAL_WINDOW_SIZE value we advertise in SETTINGS. */
    if (send_window_update(conn, 0, H2_TARGET_WINDOW - H2_RFC_INITIAL_WINDOW,
                           error, error_len) != 0)
        return -1;

    return 0;
}

void http2_cleanup(struct connection *conn) {
    struct h2_connection *h2 = conn->h2;
    if (h2 == NULL) return;

    if (!h2->goaway_sent) {
        send_goaway(conn, h2->last_stream_id, H2_NO_ERROR, NULL, 0);
        h2->goaway_sent = true;
    }

    for (size_t i = 0; i < h2->dyn_table.count; i++)
        hpack_entry_free(&h2->dyn_table.entries[i]);
    free(h2->dyn_table.entries);
    free(h2->streams);
    free(h2);
    conn->h2 = NULL;
}
