#define _GNU_SOURCE
#include "curldbg.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#ifdef __linux__
#include <endian.h>
#else
#include <machine/endian.h>
#endif

#define H2_FRAME_HEADER_SIZE 9
#define H2_CLIENT_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define H2_DEFAULT_MAX_FRAME_SIZE 16384
#define H2_TARGET_WINDOW 1048576
#define H2_SETTINGS_MAX_FRAME_SIZE 5
#define H2_MAX_DYNAMIC_TABLE_SIZE 4096
#define H2_MAX_STREAMS 256
#define H2_WINDOW_UPDATE_THRESHOLD (H2_TARGET_WINDOW / 2)

/* RFC 7540 Section 6.9.1: initial flow-control window is 65535 */
#define H2_RFC_INITIAL_WINDOW 65535
#define H2_MAX_HEADER_NAME_LEN 4096
#define H2_MAX_HEADER_VALUE_LEN 65536

enum h2_frame_type {
    H2_DATA = 0x0,
    H2_HEADERS = 0x1,
    H2_PRIORITY = 0x2,
    H2_RST_STREAM = 0x3,
    H2_SETTINGS = 0x4,
    H2_PUSH_PROMISE = 0x5,
    H2_PING = 0x6,
    H2_GOAWAY = 0x7,
    H2_WINDOW_UPDATE = 0x8,
    H2_CONTINUATION = 0x9,
};

enum h2_settings_id {
    H2_SETTINGS_HEADER_TABLE_SIZE = 1,
    H2_SETTINGS_ENABLE_PUSH = 2,
    H2_SETTINGS_MAX_CONCURRENT_STREAMS = 3,
    H2_SETTINGS_INITIAL_WINDOW_SIZE = 4,
    H2_SETTINGS_MAX_FRAME_SIZE_ID = 5,
    H2_SETTINGS_MAX_HEADER_LIST_SIZE = 6,
};

enum h2_flags {
    H2_FLAG_END_STREAM = 0x1,
    H2_FLAG_END_HEADERS = 0x4,
    H2_FLAG_PADDED = 0x8,
    H2_FLAG_PRIORITY = 0x20,
    H2_FLAG_SETTINGS_ACK = 0x1,
};

enum h2_stream_state {
    H2_SS_IDLE,
    H2_SS_OPEN,
    H2_SS_HALF_CLOSED_LOCAL,
    H2_SS_HALF_CLOSED_REMOTE,
    H2_SS_CLOSED,
};

enum h2_error_code {
    H2_NO_ERROR = 0x0,
    H2_PROTOCOL_ERROR = 0x1,
    H2_INTERNAL_ERROR = 0x2,
    H2_FLOW_CONTROL_ERROR = 0x3,
    H2_SETTINGS_TIMEOUT = 0x4,
    H2_STREAM_CLOSED = 0x5,
    H2_FRAME_SIZE_ERROR = 0x6,
    H2_REFUSED_STREAM = 0x7,
    H2_CANCEL = 0x8,
    H2_COMPRESSION_ERROR = 0x9,
    H2_CONNECT_ERROR = 0xA,
    H2_ENHANCE_YOUR_CALM = 0xB,
    H2_INADEQUATE_SECURITY = 0xC,
    H2_HTTP_1_1_REQUIRED = 0xD,
};

struct h2_hpack_entry {
    char *name;
    char *value;
    size_t name_len;
    size_t value_len;
};

struct h2_hpack_table {
    struct h2_hpack_entry *entries;
    size_t count;
    size_t capacity;
    size_t max_size;
    size_t size;
};


struct huff_node {
    uint32_t child[2];
};

struct h2_stream {
    uint32_t id;
    enum h2_stream_state state;
    int32_t window;
    bool active;
    bool done;
    bool continuation_pending;
    bool trailers_pending;
    bool saw_regular_header;
    struct response_info *out;
    FILE *body_out;
    struct timespec first_byte_ts;
    bool seen_first_byte;
    size_t recv_window_consumed;
    uint64_t recv_data_len;
    uint32_t header_list_size;
};

struct h2_settings {
    uint32_t max_frame_size;
    uint32_t initial_window_size;
    uint32_t header_table_size;
    uint32_t max_concurrent_streams;
    uint32_t max_header_list_size;
    bool enable_push;
};

struct h2_connection {
    uint32_t last_stream_id;
    int32_t conn_window;
    struct h2_settings settings;
    uint32_t goaway_last_stream_id;
    uint32_t active_stream_count;
    bool settings_received;
    bool goaway_received;
    bool goaway_graceful;
    bool goaway_sent;
    size_t conn_window_consumed;
    struct h2_hpack_table dyn_table;
    struct huff_node *huff_tree;
    int huff_tree_alloc;
    struct h2_stream streams[H2_MAX_STREAMS];
};

static uint32_t read24(const unsigned char *p) {
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

static void write24(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v >> 16);
    p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)v;
}

static int conn_write(struct connection *conn, const char *buf, size_t len,
                      char *error, size_t error_len) {
    if (connection_write_all(conn, buf, len, error, error_len) != 0)
        return -1;
    return 0;
}

static int conn_readable(struct connection *conn, int timeout_ms) {
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

static int conn_read(struct connection *conn, char *buf, size_t len,
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

static int send_frame_raw(struct connection *conn, size_t length, uint8_t type,
                          uint8_t flags, uint32_t stream_id,
                          const char *payload, char *error, size_t error_len) {
    unsigned char header[H2_FRAME_HEADER_SIZE];
    write24(header, (uint32_t)length);
    header[3] = type;
    header[4] = flags;
    header[5] = (unsigned char)((stream_id >> 24) & 0x7F);
    header[6] = (unsigned char)(stream_id >> 16);
    header[7] = (unsigned char)(stream_id >> 8);
    header[8] = (unsigned char)stream_id;

    if (conn_write(conn, (char *)header, sizeof(header), error, error_len) != 0)
        return -1;
    if (length > 0 && conn_write(conn, payload, length, error, error_len) != 0)
        return -1;
    return 0;
}

static int send_goaway(struct connection *conn, uint32_t last_stream_id,
                        uint32_t error_code,
                        char *error, size_t error_len) {
    unsigned char payload[8] = {0};
    payload[0] = (unsigned char)((last_stream_id >> 24) & 0x7F);
    payload[1] = (unsigned char)(last_stream_id >> 16);
    payload[2] = (unsigned char)(last_stream_id >> 8);
    payload[3] = (unsigned char)last_stream_id;
    payload[4] = (unsigned char)(error_code >> 24);
    payload[5] = (unsigned char)(error_code >> 16);
    payload[6] = (unsigned char)(error_code >> 8);
    payload[7] = (unsigned char)error_code;
    return send_frame_raw(conn, 8, H2_GOAWAY, 0, 0,
                          (char *)payload, error, error_len);
}

static int send_client_settings(struct connection *conn, char *error, size_t error_len) {
    unsigned char payload[18];
    payload[0] = (unsigned char)(H2_SETTINGS_MAX_CONCURRENT_STREAMS >> 8);
    payload[1] = (unsigned char)H2_SETTINGS_MAX_CONCURRENT_STREAMS;
    payload[2] = 0; payload[3] = 0; payload[4] = 0; payload[5] = 100;
    payload[6] = (unsigned char)(H2_SETTINGS_ENABLE_PUSH >> 8);
    payload[7] = (unsigned char)H2_SETTINGS_ENABLE_PUSH;
    payload[8] = 0; payload[9] = 0; payload[10] = 0; payload[11] = 0;
    payload[12] = (unsigned char)(H2_SETTINGS_INITIAL_WINDOW_SIZE >> 8);
    payload[13] = (unsigned char)H2_SETTINGS_INITIAL_WINDOW_SIZE;
    payload[14] = (unsigned char)(H2_TARGET_WINDOW >> 24);
    payload[15] = (unsigned char)(H2_TARGET_WINDOW >> 16);
    payload[16] = (unsigned char)(H2_TARGET_WINDOW >> 8);
    payload[17] = (unsigned char)H2_TARGET_WINDOW;
    return send_frame_raw(conn, 18, H2_SETTINGS, 0, 0,
                          (char *)payload, error, error_len);
}

static int send_settings_ack(struct connection *conn, char *error, size_t error_len) {
    return send_frame_raw(conn, 0, H2_SETTINGS, H2_FLAG_SETTINGS_ACK, 0, NULL, error, error_len);
}

static int send_window_update(struct connection *conn, uint32_t stream_id,
                              uint32_t increment, char *error, size_t error_len) {
    unsigned char payload[4];
    payload[0] = (unsigned char)(increment >> 24);
    payload[1] = (unsigned char)(increment >> 16);
    payload[2] = (unsigned char)(increment >> 8);
    payload[3] = (unsigned char)increment;
    return send_frame_raw(conn, 4, H2_WINDOW_UPDATE, 0, stream_id,
                          (char *)payload, error, error_len);
}

static int send_rst_stream(struct connection *conn, uint32_t stream_id,
                            uint32_t error_code, char *error, size_t error_len) {
    unsigned char payload[4];
    payload[0] = (unsigned char)(error_code >> 24);
    payload[1] = (unsigned char)(error_code >> 16);
    payload[2] = (unsigned char)(error_code >> 8);
    payload[3] = (unsigned char)error_code;
    return send_frame_raw(conn, 4, H2_RST_STREAM, 0, stream_id,
                          (char *)payload, error, error_len);
}

static int send_ping_ack(struct connection *conn, const char *data,
                          char *error, size_t error_len) {
    return send_frame_raw(conn, 8, H2_PING, 0x1, 0, data, error, error_len);
}

bool http2_negotiated(const struct connection *conn) {
    return conn != NULL && conn->http2;
}

static struct h2_stream *stream_by_id(struct h2_connection *h2, uint32_t id) {
    for (size_t i = 0; i < H2_MAX_STREAMS; i++) {
        if (h2->streams[i].active && h2->streams[i].id == id)
            return &h2->streams[i];
    }
    return NULL;
}

static struct h2_stream *alloc_stream(struct h2_connection *h2) {
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

static void free_stream(struct h2_connection *h2, struct h2_stream *s) {
    s->active = false;
    s->done = true;
    if (h2->active_stream_count > 0) h2->active_stream_count--;
}

static void flush_window_updates(struct connection *conn, struct h2_connection *h2,
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

static void hpack_entry_free(struct h2_hpack_entry *e) {
    free(e->name);
    free(e->value);
    e->name = NULL;
    e->value = NULL;
    e->name_len = 0;
    e->value_len = 0;
}

static void hpack_table_evict(struct h2_hpack_table *dyn) {
    while (dyn->size > dyn->max_size && dyn->count > 0) {
        struct h2_hpack_entry *last = &dyn->entries[dyn->count - 1];
        dyn->size -= last->name_len + last->value_len + 32;
        hpack_entry_free(last);
        dyn->count--;
    }
}

static int hpack_table_add(struct h2_hpack_table *dyn, const char *name, size_t name_len,
                            const char *value, size_t value_len) {
    if (name_len > SIZE_MAX - value_len - 32) return -1;
    size_t entry_size = name_len + value_len + 32;
    if (entry_size > dyn->max_size) return 0;

    while (dyn->size + entry_size > dyn->max_size)
        hpack_table_evict(dyn);

    if (dyn->count >= dyn->capacity) {
        size_t new_cap = dyn->capacity * 2;
        struct h2_hpack_entry *new_entries = realloc(dyn->entries,
                                            new_cap * sizeof(struct h2_hpack_entry));
        if (new_entries == NULL) return -1;
        dyn->entries = new_entries;
        dyn->capacity = new_cap;
    }

    if (dyn->count > 0) {
        memmove(&dyn->entries[1], &dyn->entries[0],
                dyn->count * sizeof(struct h2_hpack_entry));
    }

    struct h2_hpack_entry *e = &dyn->entries[0];
    e->name = malloc(name_len + 1);
    e->value = malloc(value_len + 1);
    if (e->name == NULL || e->value == NULL) {
        free(e->name); free(e->value);
        return -1;
    }
    memcpy(e->name, name, name_len);
    e->name[name_len] = '\0';
    memcpy(e->value, value, value_len);
    e->value[value_len] = '\0';
    e->name_len = name_len;
    e->value_len = value_len;
    dyn->count++;
    dyn->size += entry_size;
    return 0;
}

static void hpack_table_set_max_size(struct h2_hpack_table *dyn, uint32_t new_size) {
    dyn->max_size = new_size;
    hpack_table_evict(dyn);
}

struct h2_static_entry {
    const char *name;
    size_t name_len;
    const char *value;
    size_t value_len;
};

#define ST(x) x, sizeof(x) - 1

static const struct h2_static_entry h2_static_table[62] = {
    [1]  = { ST(":authority"), ST("") },
    [2]  = { ST(":method"), ST("GET") },
    [3]  = { ST(":method"), ST("POST") },
    [4]  = { ST(":path"), ST("/") },
    [5]  = { ST(":path"), ST("/index.html") },
    [6]  = { ST(":scheme"), ST("http") },
    [7]  = { ST(":scheme"), ST("https") },
    [8]  = { ST(":status"), ST("200") },
    [9]  = { ST(":status"), ST("204") },
    [10] = { ST(":status"), ST("206") },
    [11] = { ST(":status"), ST("304") },
    [12] = { ST(":status"), ST("400") },
    [13] = { ST(":status"), ST("404") },
    [14] = { ST(":status"), ST("500") },
    [15] = { ST("accept-charset"), ST("") },
    [16] = { ST("accept-encoding"), ST("") },
    [17] = { ST("accept-language"), ST("") },
    [18] = { ST("accept-ranges"), ST("") },
    [19] = { ST("accept"), ST("") },
    [20] = { ST("access-control-allow-origin"), ST("") },
    [21] = { ST("age"), ST("") },
    [22] = { ST("allow"), ST("") },
    [23] = { ST("authorization"), ST("") },
    [24] = { ST("cache-control"), ST("") },
    [25] = { ST("content-disposition"), ST("") },
    [26] = { ST("content-encoding"), ST("") },
    [27] = { ST("content-language"), ST("") },
    [28] = { ST("content-length"), ST("") },
    [29] = { ST("content-location"), ST("") },
    [30] = { ST("content-range"), ST("") },
    [31] = { ST("content-type"), ST("") },
    [32] = { ST("cookie"), ST("") },
    [33] = { ST("date"), ST("") },
    [34] = { ST("etag"), ST("") },
    [35] = { ST("expect"), ST("") },
    [36] = { ST("expires"), ST("") },
    [37] = { ST("from"), ST("") },
    [38] = { ST("host"), ST("") },
    [39] = { ST("if-match"), ST("") },
    [40] = { ST("if-modified-since"), ST("") },
    [41] = { ST("if-none-match"), ST("") },
    [42] = { ST("if-range"), ST("") },
    [43] = { ST("if-unmodified-since"), ST("") },
    [44] = { ST("last-modified"), ST("") },
    [45] = { ST("link"), ST("") },
    [46] = { ST("location"), ST("") },
    [47] = { ST("max-forwards"), ST("") },
    [48] = { ST("proxy-authenticate"), ST("") },
    [49] = { ST("proxy-authorization"), ST("") },
    [50] = { ST("range"), ST("") },
    [51] = { ST("referer"), ST("") },
    [52] = { ST("refresh"), ST("") },
    [53] = { ST("retry-after"), ST("") },
    [54] = { ST("server"), ST("") },
    [55] = { ST("set-cookie"), ST("") },
    [56] = { ST("strict-transport-security"), ST("") },
    [57] = { ST("transfer-encoding"), ST("") },
    [58] = { ST("user-agent"), ST("") },
    [59] = { ST("vary"), ST("") },
    [60] = { ST("via"), ST("") },
    [61] = { ST("www-authenticate"), ST("") },
};

static int lookup_static_name(const char *name, size_t name_len, int *idx_out) {
    for (int i = 1; i < 62; i++) {
        if (h2_static_table[i].name_len == name_len &&
            memcmp(h2_static_table[i].name, name, name_len) == 0) {
            *idx_out = i;
            return 0;
        }
    }
    return -1;
}

static const struct h2_static_entry *get_static_entry(int idx) {
    if (idx >= 1 && idx < 62) return &h2_static_table[idx];
    return NULL;
}

static size_t hpack_encode_int(unsigned char *out, size_t out_size,
                                uint64_t value, uint8_t prefix_bits) {
    uint8_t prefix_mask = (uint8_t)((1 << prefix_bits) - 1);
    if (prefix_bits == 0) prefix_mask = 0;

    if (value < (uint64_t)prefix_mask || prefix_bits == 0) {
        if (out_size < 1) return 0;
        out[0] = (uint8_t)((prefix_bits > 0 ? (out[0] & ~prefix_mask) : 0) | (value & prefix_mask));
        return 1;
    }
    if (out_size < 1) return 0;
    out[0] = (uint8_t)((out[0] & ~prefix_mask) | prefix_mask);
    value -= prefix_mask;
    size_t off = 1;
    while (value >= 128) {
        if (off >= out_size) return 0;
        out[off++] = (uint8_t)(value & 0x7F) | 0x80;
        value >>= 7;
    }
    if (off >= out_size) return 0;
    out[off++] = (uint8_t)value;
    return off;
}

static int hpack_decode_int(const unsigned char *buf, size_t buf_len,
                             size_t *offset, uint8_t prefix_bits,
                             uint64_t *out) {
    uint64_t prefix_mask = (uint64_t)((1 << prefix_bits) - 1);
    if (prefix_bits == 0) prefix_mask = 0;

    if (*offset >= buf_len) return -1;
    uint8_t b = buf[*offset];
    *offset += 1;
    uint64_t value = b & prefix_mask;
    if (value < prefix_mask || prefix_bits == 0) {
        *out = value;
        return 0;
    }
    int shift = 0;
    value = prefix_mask;
    for (;;) {
        if (*offset >= buf_len) return -1;
        b = buf[*offset];
        *offset += 1;
        uint64_t add = (uint64_t)(b & 0x7F) << shift;
        if (value > UINT64_MAX - add) return -1;
        value += add;
        if ((b & 0x80) == 0) break;
        shift += 7;
        if (shift > 63) return -1;
    }
    *out = value;
    return 0;
}

static const uint32_t huff_sym[256] = {
    0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7,
    0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec,
    0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3,
    0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb,
    0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa,
    0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18,
    0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb, 0x3fc,
    0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
    0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
    0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72,
    0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0, 0x1ffc, 0x3ffc, 0x22,
    0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26,
    0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x7,
    0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78,
    0x79, 0x7a, 0x7b, 0x7ffe, 0x7fc, 0x3ffd, 0x1ffd, 0xffffffc,
    0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9,
    0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf,
    0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3,
    0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef,
    0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde,
    0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec,
    0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef,
    0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1,
    0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec,
    0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5, 0xfffff1, 0x1ffffed,
    0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7, 0x7ffffe2, 0xfffff2,
    0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5,
    0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3,
    0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4,
    0x3ffffeb, 0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea,
    0x7ffffeb, 0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
};

static const uint8_t huff_nbits[256] = {
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
    5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
    13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
    15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
    6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
};

#define HUFF_EOS 256
#define HUFF_EOS_CODE 0x3fffffff
#define HUFF_EOS_BITS 30

size_t huffman_encode(const unsigned char *input, size_t input_len,
                              unsigned char *output, size_t output_size) {
    uint64_t buffer = 0;
    int bits = 0;
    size_t out_pos = 0;

    for (size_t i = 0; i < input_len; i++) {
        uint8_t c = input[i];
        uint32_t code = huff_sym[c];
        uint8_t nbits = huff_nbits[c];
        buffer = (buffer << nbits) | code;
        bits += nbits;
        while (bits >= 8) {
            if (out_pos >= output_size) return 0;
            bits -= 8;
            output[out_pos++] = (unsigned char)(buffer >> bits);
        }
    }

    if (bits > 0) {
        if (out_pos >= output_size) return 0;
        buffer = (buffer << (8 - bits)) | (uint64_t)((1U << (8 - bits)) - 1);
        output[out_pos++] = (unsigned char)buffer;
    }

    return out_pos;
}

int huff_tree_init(struct huff_node **tree, int *alloc) {
    if (*tree != NULL) return 0;
    *alloc = 512;
    *tree = calloc((size_t)*alloc, sizeof(struct huff_node));
    if (*tree == NULL) return -1;

    int node_count = 1;
    for (int sym = 0; sym < 256; sym++) {
        uint32_t code = huff_sym[sym];
        int nbits = huff_nbits[sym];
        if (nbits == 0) continue;
        int node = 0;

        for (int b = nbits - 1; b >= 0; b--) {
            int bit = (code >> b) & 1;
            if (b > 0) {
                if ((*tree)[node].child[bit] == 0) {
                    if (node_count >= *alloc) {
                        *alloc *= 2;
                        struct huff_node *tmp = realloc(*tree,
                                              (size_t)*alloc * sizeof(struct huff_node));
                        if (tmp == NULL) return -1;
                        *tree = tmp;
                        memset(&(*tree)[node_count], 0,
                               (size_t)(*alloc - node_count) * sizeof(struct huff_node));
                    }
                    (*tree)[node].child[bit] = (uint32_t)node_count;
                    node_count++;
                }
                node = (int)((*tree)[node].child[bit]);
            } else {
                (*tree)[node].child[bit] = (uint32_t)sym | HUFF_NODE_TERMINAL;
            }
        }
    }
    return 0;
}

size_t huffman_decode(const struct huff_node *tree,
                              const unsigned char *input, size_t input_len,
                              unsigned char *output, size_t output_size) {
    if (tree == NULL) return 0;

    int node = 0;
    size_t out_pos = 0;

    for (size_t i = 0; i < input_len; i++) {
        for (int b = 7; b >= 0; b--) {
            int bit = (input[i] >> b) & 1;
            uint32_t child = tree[node].child[bit];
            if (child == 0) {
                if (node == 0) continue;
                return 0;
            }
            if (child & HUFF_NODE_TERMINAL) {
                unsigned char sym = (unsigned char)(child & ~HUFF_NODE_TERMINAL);
                if (out_pos < output_size) {
                    output[out_pos++] = sym;
                } else {
                    return 0;
                }
                node = 0;
            } else {
                node = (int)child;
            }
        }
    }

    (void)node;
    return out_pos;
}

static size_t hpack_encode_string(unsigned char *out, size_t out_size,
                                   const char *str, size_t str_len) {
    size_t off = 0;
    if (out_size < 1) return 0;

    unsigned char huff_buf[4096];
    size_t huff_len = 0;
    bool use_huffman = false;

    if (str_len > 0 && str_len < sizeof(huff_buf)) {
        huff_len = huffman_encode((const unsigned char *)str, str_len,
                                   huff_buf, sizeof(huff_buf));
        if (huff_len > 0 && huff_len < str_len)
            use_huffman = true;
    }

    size_t enc_len = use_huffman ? huff_len : str_len;
    out[off] = use_huffman ? (unsigned char)0x80 : (unsigned char)0x00;

    size_t n = hpack_encode_int(out, out_size, (uint64_t)enc_len, 7);
    if (n == 0) return 0;
    off = n;

    if (off + enc_len > out_size) return 0;
    if (use_huffman)
        memcpy(out + off, huff_buf, enc_len);
    else
        memcpy(out + off, str, enc_len);
    off += enc_len;
    return off;
}

static int hpack_decode_string(struct h2_connection *h2,
                                const unsigned char *buf, size_t buf_len,
                                size_t *offset, char *out, size_t out_size,
                                size_t *out_len) {
    if (*offset >= buf_len) return -1;
    bool huffman = (buf[*offset] & 0x80) != 0;

    uint64_t len64;
    if (hpack_decode_int(buf, buf_len, offset, 7, &len64) != 0)
        return -1;
    if (len64 > buf_len - *offset) return -1;
    if (len64 > out_size) return -1;
    size_t slen = (size_t)len64;

    if (huffman) {
        size_t decoded = huffman_decode(h2->huff_tree, buf + *offset, slen,
                                         (unsigned char *)out, out_size);
        if (decoded == 0 || decoded >= out_size) return -1;
        out[decoded] = '\0';
        *out_len = decoded;
    } else {
        if (slen >= out_size) return -1;
        memcpy(out, buf + *offset, slen);
        out[slen] = '\0';
        *out_len = slen;
    }
    *offset += slen;
    return 0;
}

static int hpack_encode_literal_with_indexing(unsigned char *out, size_t out_size,
                                               uint64_t name_index,
                                               const char *name, size_t name_len,
                                               const char *value, size_t value_len) {
    size_t off = 0;
    out[off] = 0x40;

    if (name_index > 0) {
        size_t n = hpack_encode_int(out, out_size, name_index, 4);
        if (n == 0) return -1;
        off = n;
    } else {
        size_t n = hpack_encode_int(out, out_size, 0, 4);
        if (n == 0) return -1;
        off = n;
        size_t sn = hpack_encode_string(out + off, out_size - off, name, name_len);
        if (sn == 0) return -1;
        off += sn;
    }

    size_t sv = hpack_encode_string(out + off, out_size - off, value, value_len);
    if (sv == 0) return -1;
    off += sv;
    return (int)off;
}

static int hpack_encode_literal_without_indexing(unsigned char *out, size_t out_size,
                                                  uint64_t name_index,
                                                  const char *name, size_t name_len,
                                                  const char *value, size_t value_len) {
    size_t off = 0;
    out[off] = 0x00;

    size_t n = hpack_encode_int(out, out_size, name_index, 4);
    if (n == 0) return -1;
    off = n;

    if (name_index == 0) {
        size_t sn = hpack_encode_string(out + off, out_size - off, name, name_len);
        if (sn == 0) return -1;
        off += sn;
    }

    size_t sv = hpack_encode_string(out + off, out_size - off, value, value_len);
    if (sv == 0) return -1;
    off += sv;
    return (int)off;
}

static int get_table_entry(struct h2_hpack_table *dyn, int index,
                            const char **name, size_t *name_len,
                            const char **value, size_t *value_len) {
    if (index >= 1 && index < 62) {
        const struct h2_static_entry *e = get_static_entry(index);
        if (e == NULL) return -1;
        *name = e->name;
        *name_len = e->name_len;
        *value = e->value;
        *value_len = e->value_len;
        return 0;
    }
    int dyn_idx = index - 62;
    if (dyn_idx >= 0 && (size_t)dyn_idx < dyn->count) {
        const struct h2_hpack_entry *e = &dyn->entries[dyn_idx];
        *name = e->name;
        *name_len = e->name_len;
        *value = e->value;
        *value_len = e->value_len;
        return 0;
    }
    return -1;
}

int http2_init_connection(struct connection *conn, char *error, size_t error_len) {
    struct h2_connection *h2 = calloc(1, sizeof(struct h2_connection));
    if (h2 == NULL) {
        set_error(error, error_len, "Out of memory");
        return -1;
    }
    conn->h2 = h2;

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

    if (huff_tree_init(&h2->huff_tree, &h2->huff_tree_alloc) != 0) {
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
            const unsigned char *p = (const unsigned char *)payload;
            for (size_t off = 0; off + 6 <= length; off += 6) {
                uint16_t id = (uint16_t)(p[off] << 8) | p[off + 1];
                for (size_t j = 0; j < off; j += 6) {
                    uint16_t prev = (uint16_t)(p[j] << 8) | p[j + 1];
                    if (prev == id) {
                        free(payload);
                        set_error(error, error_len,
                            "Duplicate setting identifier in SETTINGS frame");
                        return -1;
                    }
                }
                uint32_t val = (uint32_t)(p[off + 2] << 24) | (p[off + 3] << 16) |
                               (p[off + 4] << 8) | p[off + 5];
                switch (id) {
                    case H2_SETTINGS_HEADER_TABLE_SIZE:
                        h2->settings.header_table_size = val;
                        hpack_table_set_max_size(&h2->dyn_table, val);
                        break;
                    case H2_SETTINGS_INITIAL_WINDOW_SIZE:
                        if (val > 2147483647u) {
                            free(payload);
                            set_error(error, error_len, "Invalid initial window size");
                            return -1;
                        }
                        h2->settings.initial_window_size = val;
                        break;
                    case H2_SETTINGS_MAX_FRAME_SIZE_ID:
                        if (val < 16384 || val > 16777215) {
                            free(payload);
                            set_error(error, error_len, "Invalid max frame size");
                            return -1;
                        }
                        h2->settings.max_frame_size = val;
                        break;
                    case H2_SETTINGS_ENABLE_PUSH:
                        if (val > 1) {
                            free(payload);
                            set_error(error, error_len, "Invalid SETTINGS_ENABLE_PUSH value");
                            return -1;
                        }
                        h2->settings.enable_push = (val == 1);
                        break;
                    case H2_SETTINGS_MAX_CONCURRENT_STREAMS:
                        h2->settings.max_concurrent_streams = val;
                        break;
                    case H2_SETTINGS_MAX_HEADER_LIST_SIZE:
                        h2->settings.max_header_list_size = val;
                        break;
                }
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

    if (!got_settings) {
        set_error(error, error_len, "HTTP/2 never received server SETTINGS");
        return -1;
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

uint32_t http2_send_request(struct connection *conn, const struct url_info *url,
                            const char *method, const char *data, size_t data_len,
                            const char **extra_headers, size_t extra_header_count,
                            const char *user_agent, const char *basic_auth,
                            char *error, size_t error_len) {
    struct h2_connection *h2 = conn->h2;
    (void)error;
    (void)error_len;
    if (user_agent == NULL) user_agent = "curldbg/1.0";

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

    unsigned char block[65536];
    size_t block_len = 0;
    int n;

    n = hpack_encode_literal_with_indexing(block, sizeof(block), 0,
                                            ":method", 7, method, strlen(method));
    if (n < 0) { set_error(error, error_len, "HPACK encode failed"); free_stream(h2, s); return 0; }
    block_len = (size_t)n;

    if (!is_connect) {
        n = hpack_encode_literal_with_indexing(block + block_len, sizeof(block) - block_len, 0,
                                                ":scheme", 7, scheme, strlen(scheme));
        if (n < 0) { set_error(error, error_len, "HPACK encode failed"); free_stream(h2, s); return 0; }
        block_len += (size_t)n;
    }

    n = hpack_encode_literal_with_indexing(block + block_len, sizeof(block) - block_len, 0,
                                            ":authority", 10, host_header, strlen(host_header));
    if (n < 0) { set_error(error, error_len, "HPACK encode failed"); free_stream(h2, s); return 0; }
    block_len += (size_t)n;

    if (!is_connect) {
        n = hpack_encode_literal_without_indexing(block + block_len, sizeof(block) - block_len, 0,
                                                   ":path", 5, url->path, strlen(url->path));
        if (n < 0) { set_error(error, error_len, "HPACK encode failed"); free_stream(h2, s); return 0; }
        block_len += (size_t)n;
    }

    n = hpack_encode_literal_without_indexing(block + block_len, sizeof(block) - block_len, 0,
                                               "user-agent", 10, user_agent, strlen(user_agent));
    if (n < 0) { set_error(error, error_len, "HPACK encode failed"); free_stream(h2, s); return 0; }
    block_len += (size_t)n;

    if (basic_auth != NULL && basic_auth[0] != '\0') {
        char auth_b64[512];
        char auth_header[1024];
        if (base64_encode((const unsigned char *)basic_auth, strlen(basic_auth),
                           auth_b64, sizeof(auth_b64)) != 0) {
            free_stream(h2, s);
            set_error(error, error_len, "Basic auth value too large");
            return 0;
        }
        int na = snprintf(auth_header, sizeof(auth_header), "Basic %s", auth_b64);
        if (na < 0 || (size_t)na >= sizeof(auth_header)) {
            free_stream(h2, s);
            set_error(error, error_len, "Authorization header too large");
            return 0;
        }
        n = hpack_encode_literal_without_indexing(block + block_len, sizeof(block) - block_len,
                                                   0, "authorization", 13,
                                                   auth_header, (size_t)na);
        if (n < 0) { set_error(error, error_len, "HPACK encode failed"); free_stream(h2, s); return 0; }
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

        n = hpack_encode_literal_without_indexing(block + block_len, sizeof(block) - block_len,
                                                   (uint64_t)name_idx,
                                                   lc_name, lc_len, val, val_len);
        if (n < 0) { set_error(error, error_len, "HPACK encode failed"); free_stream(h2, s); return 0; }
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
            { free_stream(h2, s); return 0; }
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
                { free_stream(h2, s); return 0; }
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
                    free_stream(h2, s); return 0;
                }
                if (conn_read(conn, (char *)whdr, sizeof(whdr), error, error_len) != 0)
                    { free_stream(h2, s); return 0; }
                size_t wlen = read24(whdr);
                uint8_t wtype = whdr[3];
                uint32_t wfid = (((uint32_t)(whdr[5] & 0x7F) << 24) |
                                 ((uint32_t)whdr[6] << 16) |
                                 ((uint32_t)whdr[7] << 8) |
                                 (uint32_t)whdr[8]);
                if (wtype == H2_WINDOW_UPDATE && wlen >= 4) {
                    char wpayload[4];
                    if (conn_read(conn, wpayload, 4, error, error_len) != 0)
                        { free_stream(h2, s); return 0; }
                    uint32_t inc = (uint32_t)((unsigned char)wpayload[0] << 24) |
                                   (uint32_t)((unsigned char)wpayload[1] << 16) |
                                   (uint32_t)((unsigned char)wpayload[2] << 8) |
                                   (unsigned char)wpayload[3];
                    if (inc < (1u << 31)) {
                        if (wfid == 0) {
                            if ((int32_t)(0x7FFFFFFF - h2->conn_window) < (int32_t)inc) {
                                free_stream(h2, s); return 0;
                            }
                            h2->conn_window += (int32_t)inc;
                        } else if (wfid == stream_id) {
                            if ((int32_t)(0x7FFFFFFF - s->window) < (int32_t)inc) {
                                free_stream(h2, s); return 0;
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
                                { free_stream(h2, s); return 0; }
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
                        free_stream(h2, s); return 0;
                    }
                    if (wtype == H2_RST_STREAM && wfid == stream_id) {
                        if (wlen > 0) {
                            char *skip = malloc(wlen);
                            if (skip) { conn_read(conn, skip, wlen, error, error_len); free(skip); }
                        }
                        set_error(error, error_len, "HTTP/2 stream reset while sending body");
                        free_stream(h2, s); return 0;
                    }
                    if (wtype == H2_SETTINGS) {
                        if (wlen > 0) {
                            char *wp = malloc(wlen);
                            if (wp) {
                                conn_read(conn, wp, wlen, error, error_len);
                                for (size_t off = 0; off + 6 <= wlen; off += 6) {
                                    uint16_t sid = (uint16_t)((unsigned char)wp[off] << 8) | (unsigned char)wp[off + 1];
                                    uint32_t sv = (uint32_t)((unsigned char)wp[off + 2] << 24) |
                                                  ((uint32_t)(unsigned char)wp[off + 3] << 16) |
                                                  ((uint32_t)(unsigned char)wp[off + 4] << 8) |
                                                  (unsigned char)wp[off + 5];
                                    if (sid == H2_SETTINGS_INITIAL_WINDOW_SIZE && sv <= 2147483647u) {
                                        int32_t delta = (int32_t)sv - (int32_t)h2->settings.initial_window_size;
                                        h2->settings.initial_window_size = sv;
                                        for (size_t i = 0; i < H2_MAX_STREAMS; i++)
                                            if (h2->streams[i].active) h2->streams[i].window += delta;
                                    } else if (sid == H2_SETTINGS_MAX_FRAME_SIZE_ID && sv >= 16384 && sv <= 16777215) {
                                        h2->settings.max_frame_size = sv;
                                    } else if (sid == H2_SETTINGS_HEADER_TABLE_SIZE) {
                                        h2->settings.header_table_size = sv;
                                        hpack_table_set_max_size(&h2->dyn_table, sv);
                                    } else if (sid == H2_SETTINGS_ENABLE_PUSH && sv <= 1) {
                                        h2->settings.enable_push = (sv == 1);
                                    } else if (sid == H2_SETTINGS_MAX_CONCURRENT_STREAMS) {
                                        h2->settings.max_concurrent_streams = sv;
                                    } else if (sid == H2_SETTINGS_MAX_HEADER_LIST_SIZE) {
                                        h2->settings.max_header_list_size = sv;
                                    }
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
                { free_stream(h2, s); return 0; }
            h2->conn_window -= (int32_t)chunk;
            s->window -= (int32_t)chunk;
            remaining -= chunk;
            ptr += chunk;
        }
        s->state = H2_SS_HALF_CLOSED_LOCAL;
    }

    return stream_id;
}

static void parse_h2_header(const char *name, const char *value,
                             struct response_info *out) {
    if (strcasecmp(name, ":status") == 0) {
        out->status_code = (int)strtol(value, NULL, 10);
    } else if (strcasecmp(name, "content-length") == 0) {
        char *endp = NULL;
        long cl = strtol(value, &endp, 10);
        if (endp != NULL && *endp == '\0' && cl >= 0)
            out->content_length = cl;
    } else if (strcasecmp(name, "content-encoding") == 0) {
        snprintf(out->content_encoding, sizeof(out->content_encoding), "%s", value);
    } else if (strcasecmp(name, "location") == 0) {
        snprintf(out->location, sizeof(out->location), "%s", value);
    } else if (strcasecmp(name, "set-cookie") == 0) {
        size_t vlen = strlen(value);
        if (out->set_cookie_len + vlen + 1 < sizeof(out->set_cookie_buf)) {
            if (out->set_cookie_len > 0)
                out->set_cookie_buf[out->set_cookie_len++] = '\n';
            memcpy(out->set_cookie_buf + out->set_cookie_len, value, vlen);
            out->set_cookie_len += vlen;
            out->set_cookie_buf[out->set_cookie_len] = '\0';
        }
    }
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
    out->preview_len = 0;
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
            const unsigned char *p = (const unsigned char *)payload;
            for (size_t off = 0; off + 6 <= length; off += 6) {
                uint16_t id = (uint16_t)(p[off] << 8) | p[off + 1];
                for (size_t j = 0; j < off; j += 6) {
                    uint16_t prev = (uint16_t)(p[j] << 8) | p[j + 1];
                    if (prev == id) {
                        free(payload);
                        set_error(error, error_len,
                            "Duplicate setting identifier in SETTINGS frame");
                        return -1;
                    }
                }
                uint32_t val = (uint32_t)(p[off + 2] << 24) | (p[off + 3] << 16) |
                               (p[off + 4] << 8) | p[off + 5];
                if (id == H2_SETTINGS_INITIAL_WINDOW_SIZE) {
                    if (val > 2147483647u) {
                        free(payload);
                        set_error(error, error_len, "Invalid initial window size");
                        return -1;
                    }
                    int32_t delta = (int32_t)val - (int32_t)h2->settings.initial_window_size;
                    for (size_t i = 0; i < H2_MAX_STREAMS; i++) {
                        if (h2->streams[i].active &&
                            (int32_t)(0x7FFFFFFF - h2->streams[i].window) < delta) {
                            free(payload);
                            set_error(error, error_len,
                                "SETTINGS_INITIAL_WINDOW_SIZE delta would overflow stream window");
                            return -1;
                        }
                    }
                    h2->settings.initial_window_size = val;
                    for (size_t i = 0; i < H2_MAX_STREAMS; i++) {
                        if (h2->streams[i].active)
                            h2->streams[i].window += delta;
                    }
                } else if (id == H2_SETTINGS_MAX_FRAME_SIZE_ID) {
                    if (val < 16384 || val > 16777215) {
                        free(payload);
                        set_error(error, error_len, "Invalid max frame size");
                        return -1;
                    }
                    h2->settings.max_frame_size = val;
                } else if (id == H2_SETTINGS_HEADER_TABLE_SIZE) {
                    h2->settings.header_table_size = val;
                    hpack_table_set_max_size(&h2->dyn_table, val);
                } else if (id == H2_SETTINGS_ENABLE_PUSH) {
                    if (val > 1) {
                        free(payload);
                        set_error(error, error_len, "Invalid SETTINGS_ENABLE_PUSH value");
                        return -1;
                    }
                    h2->settings.enable_push = (val == 1);
                } else if (id == H2_SETTINGS_MAX_CONCURRENT_STREAMS) {
                    h2->settings.max_concurrent_streams = val;
                } else if (id == H2_SETTINGS_MAX_HEADER_LIST_SIZE) {
                    h2->settings.max_header_list_size = val;
                }
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

            size_t hpack_len = length;
            if (hpack_off <= length) hpack_len = length - hpack_off;

            if (dst == s && !s->seen_first_byte && hpack_len > 0) {
                if (clock_gettime(CLOCK_MONOTONIC, &s->first_byte_ts) != 0) {
                    free(payload);
                    set_error(error, error_len, "clock_gettime failed");
                    return -1;
                }
                s->out->ttfb_ms = ms_between(ttfb_start, &s->first_byte_ts);
                s->seen_first_byte = true;
            }

            size_t hpack_pos = 0;
            while (hpack_pos < hpack_len) {
                unsigned char b = (unsigned char)payload[hpack_off + hpack_pos];

                if ((b & 0x80) != 0) {
                    uint64_t idx;
                    if (hpack_decode_int((const unsigned char *)payload + hpack_off,
                                         hpack_len, &hpack_pos, 7, &idx) != 0)
                        goto hpack_error;
                    const char *name, *value;
                    size_t name_len, value_len;
                    if (get_table_entry(&h2->dyn_table, (int)idx, &name, &name_len,
                                        &value, &value_len) != 0)
                        goto hpack_error;
                    if (dst->out) {
                        if (name[0] == ':') {
                            if (dst->trailers_pending || dst->saw_regular_header) {
                                send_rst_stream(conn, fid, H2_PROTOCOL_ERROR, error, error_len);
                                goto stream_reset;
                            }
                        } else {
                            dst->saw_regular_header = true;
                            for (const char *p = name; *p != '\0'; p++) {
                                if (*p >= 'A' && *p <= 'Z') {
                                    send_rst_stream(conn, fid, H2_PROTOCOL_ERROR, error, error_len);
                                    goto stream_reset;
                                }
                            }
                        }
                        parse_h2_header(name, value, dst->out);
                    }
                    dst->header_list_size += (uint32_t)(name_len + value_len + 32);
                    if (h2->settings.max_header_list_size > 0 &&
                        dst->header_list_size > h2->settings.max_header_list_size) {
                        send_rst_stream(conn, fid, H2_ENHANCE_YOUR_CALM, error, error_len);
                        goto stream_reset;
                    }
                } else if ((b & 0x40) != 0) {
                    uint64_t name_idx;
                    if (hpack_decode_int((const unsigned char *)payload + hpack_off,
                                         hpack_len, &hpack_pos, 6, &name_idx) != 0)
                        goto hpack_error;

                    char name[H2_MAX_HEADER_NAME_LEN];
                    char value[H2_MAX_HEADER_VALUE_LEN];
                    size_t name_len = 0, value_len = 0;

                    if (name_idx == 0) {
                        if (hpack_decode_string(h2,
                                                 (const unsigned char *)payload + hpack_off,
                                                 hpack_len, &hpack_pos,
                                                 name, sizeof(name), &name_len) != 0)
                            goto hpack_error;
                    } else {
                        const char *sn, *sv;
                        size_t sn_len, sv_len;
                        if (get_table_entry(&h2->dyn_table, (int)name_idx, &sn, &sn_len,
                                            &sv, &sv_len) != 0)
                            goto hpack_error;
                        name_len = sn_len;
                        if (name_len >= sizeof(name)) goto hpack_error;
                        memcpy(name, sn, name_len);
                        name[name_len] = '\0';
                    }

                    if (hpack_decode_string(h2,
                                             (const unsigned char *)payload + hpack_off,
                                             hpack_len, &hpack_pos,
                                             value, sizeof(value), &value_len) != 0)
                        goto hpack_error;

                    hpack_table_add(&h2->dyn_table, name, name_len, value, value_len);
                    if (dst->out) {
                        if (name[0] == ':') {
                            if (dst->trailers_pending || dst->saw_regular_header) {
                                send_rst_stream(conn, fid, H2_PROTOCOL_ERROR, error, error_len);
                                goto stream_reset;
                            }
                        } else {
                            dst->saw_regular_header = true;
                            for (const char *p = name; *p != '\0'; p++) {
                                if (*p >= 'A' && *p <= 'Z') {
                                    send_rst_stream(conn, fid, H2_PROTOCOL_ERROR, error, error_len);
                                    goto stream_reset;
                                }
                            }
                        }
                        parse_h2_header(name, value, dst->out);
                    }
                    dst->header_list_size += (uint32_t)(name_len + value_len + 32);
                    if (h2->settings.max_header_list_size > 0 &&
                        dst->header_list_size > h2->settings.max_header_list_size) {
                        send_rst_stream(conn, fid, H2_ENHANCE_YOUR_CALM, error, error_len);
                        goto stream_reset;
                    }
                } else if ((b & 0x20) != 0) {
                    uint64_t new_size;
                    if (hpack_decode_int((const unsigned char *)payload + hpack_off,
                                         hpack_len, &hpack_pos, 5, &new_size) != 0)
                        goto hpack_error;
                    hpack_table_set_max_size(&h2->dyn_table, (uint32_t)new_size);
                } else {
                    uint64_t name_idx;
                    if (hpack_decode_int((const unsigned char *)payload + hpack_off,
                                         hpack_len, &hpack_pos, 4, &name_idx) != 0)
                        goto hpack_error;

                    char name[H2_MAX_HEADER_NAME_LEN];
                    char value[H2_MAX_HEADER_VALUE_LEN];
                    size_t name_len = 0, value_len = 0;

                    if (name_idx == 0) {
                        if (hpack_decode_string(h2,
                                                 (const unsigned char *)payload + hpack_off,
                                                 hpack_len, &hpack_pos,
                                                 name, sizeof(name), &name_len) != 0)
                            goto hpack_error;
                    } else {
                        const char *sn, *sv;
                        size_t sn_len, sv_len;
                        if (get_table_entry(&h2->dyn_table, (int)name_idx, &sn, &sn_len,
                                            &sv, &sv_len) != 0)
                            goto hpack_error;
                        name_len = sn_len;
                        if (name_len >= sizeof(name)) goto hpack_error;
                        memcpy(name, sn, name_len);
                        name[name_len] = '\0';
                    }

                    if (hpack_decode_string(h2,
                                             (const unsigned char *)payload + hpack_off,
                                             hpack_len, &hpack_pos,
                                             value, sizeof(value), &value_len) != 0)
                        goto hpack_error;

                    if (dst->out) {
                        if (name[0] == ':') {
                            if (dst->trailers_pending || dst->saw_regular_header) {
                                send_rst_stream(conn, fid, H2_PROTOCOL_ERROR, error, error_len);
                                goto stream_reset;
                            }
                        } else {
                            dst->saw_regular_header = true;
                            for (const char *p = name; *p != '\0'; p++) {
                                if (*p >= 'A' && *p <= 'Z') {
                                    send_rst_stream(conn, fid, H2_PROTOCOL_ERROR, error, error_len);
                                    goto stream_reset;
                                }
                            }
                        }
                        parse_h2_header(name, value, dst->out);
                    }
                    dst->header_list_size += (uint32_t)(name_len + value_len + 32);
                    if (h2->settings.max_header_list_size > 0 &&
                        dst->header_list_size > h2->settings.max_header_list_size) {
                        send_rst_stream(conn, fid, H2_ENHANCE_YOUR_CALM, error, error_len);
                        goto stream_reset;
                    }
                }
            }

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
            if (dst == NULL) {
                free(payload);
                continue;
            }
            if (dst->state != H2_SS_OPEN && dst->state != H2_SS_HALF_CLOSED_LOCAL) {
                send_rst_stream(conn, fid, H2_STREAM_CLOSED, error, error_len);
                free(payload);
                continue;
            }

            size_t data_off = 0;
            if (flags & H2_FLAG_PADDED) {
                if (length < 1) { free(payload); set_error(error, error_len, "Truncated padded DATA"); return -1; }
                unsigned char pad_len = (unsigned char)payload[0];
                data_off = 1;
                if (data_off + pad_len > length) { free(payload); set_error(error, error_len, "Invalid padding in DATA"); return -1; }
            }

            size_t data_len_actual = length - data_off;

            if (data_len_actual == 0 && !(flags & H2_FLAG_END_STREAM)) {
                send_rst_stream(conn, fid, H2_ENHANCE_YOUR_CALM, error, error_len);
                free(payload);
                continue;
            }

            if (dst == s && !s->seen_first_byte && data_len_actual > 0) {
                if (clock_gettime(CLOCK_MONOTONIC, &s->first_byte_ts) != 0) {
                    free(payload);
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
                    free(payload);
                    set_error(error, error_len, "Failed to write response body");
                    return -1;
                }
                if (dst == s && s->out->preview_len < PREVIEW_BYTES) {
                    size_t take = data_len_actual;
                    if (take > PREVIEW_BYTES - s->out->preview_len)
                        take = PREVIEW_BYTES - s->out->preview_len;
                    memcpy(s->out->preview + s->out->preview_len, body_data, take);
                    s->out->preview_len += take;
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
                    free(payload);
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

    if (s->out) s->out->preview[s->out->preview_len] = '\0';
    if (!s->seen_first_byte) s->out->ttfb_ms = -1.0;
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
    free(h2->huff_tree);
    free(h2);
    conn->h2 = NULL;
}
