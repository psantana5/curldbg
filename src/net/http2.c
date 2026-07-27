#define _GNU_SOURCE
#include "curldbg.h"

#include <errno.h>
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
#define H2_DEFAULT_WINDOW 65535
#define H2_SETTINGS_MAX_FRAME_SIZE 5
#define H2_MAX_DYNAMIC_TABLE_SIZE 4096

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
    H2_SS_HALF_CLOSED,
    H2_SS_CLOSED,
};

enum h2_error_code {
    H2_NO_ERROR = 0x0,
    H2_PROTOCOL_ERROR = 0x1,
    H2_FLOW_CONTROL_ERROR = 0x3,
    H2_STREAM_CLOSED = 0x5,
    H2_REFUSED_STREAM = 0x7,
};

struct h2_connection {
    uint32_t last_stream_id;
    int32_t conn_window;
    uint32_t max_frame_size;
    uint32_t max_concurrent_streams;
    uint32_t initial_window_size;
    uint32_t header_table_size;
    bool settings_received;
    bool goaway_received;
    enum h2_stream_state stream_state;
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

static struct h2_connection h2_conn_state;
static struct h2_hpack_table h2_dyn_table;

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

static int send_empty_settings(struct connection *conn, char *error, size_t error_len) {
    return send_frame_raw(conn, 0, H2_SETTINGS, 0, 0, NULL, error, error_len);
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

static void hpack_table_init(void) {
    if (h2_dyn_table.entries == NULL) {
        h2_dyn_table.max_size = H2_MAX_DYNAMIC_TABLE_SIZE;
        h2_dyn_table.capacity = 16;
        h2_dyn_table.entries = calloc(h2_dyn_table.capacity, sizeof(struct h2_hpack_entry));
        h2_dyn_table.count = 0;
        h2_dyn_table.size = 0;
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

static void hpack_table_evict(void) {
    while (h2_dyn_table.size > h2_dyn_table.max_size && h2_dyn_table.count > 0) {
        struct h2_hpack_entry *last = &h2_dyn_table.entries[h2_dyn_table.count - 1];
        h2_dyn_table.size -= last->name_len + last->value_len + 32;
        hpack_entry_free(last);
        h2_dyn_table.count--;
    }
}

static int hpack_table_add(const char *name, size_t name_len,
                            const char *value, size_t value_len) {
    size_t entry_size = name_len + value_len + 32;
    if (entry_size > h2_dyn_table.max_size) return 0;

    while (h2_dyn_table.size + entry_size > h2_dyn_table.max_size)
        hpack_table_evict();

    if (h2_dyn_table.count >= h2_dyn_table.capacity) {
        size_t new_cap = h2_dyn_table.capacity * 2;
        struct h2_hpack_entry *new_entries = realloc(h2_dyn_table.entries,
                                           new_cap * sizeof(struct h2_hpack_entry));
        if (new_entries == NULL) return -1;
        h2_dyn_table.entries = new_entries;
        h2_dyn_table.capacity = new_cap;
    }

    if (h2_dyn_table.count > 0) {
        memmove(&h2_dyn_table.entries[1], &h2_dyn_table.entries[0],
                h2_dyn_table.count * sizeof(struct h2_hpack_entry));
    }

    struct h2_hpack_entry *e = &h2_dyn_table.entries[0];
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
    h2_dyn_table.count++;
    h2_dyn_table.size += entry_size;
    return 0;
}

static void hpack_table_set_max_size(uint32_t new_size) {
    h2_dyn_table.max_size = new_size;
    hpack_table_evict();
}

/* RFC 7541 static table */
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

/* HPACK integer encode */
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

/* HPACK integer decode */
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
        value += (uint64_t)(b & 0x7F) << shift;
        if ((b & 0x80) == 0) break;
        shift += 7;
        if (shift > 63) return -1;
    }
    *out = value;
    return 0;
}

/* Huffman tables from RFC 7541 Appendix B */
static const uint32_t huff_sym[256] = {
    0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7,
    0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec,
    0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3,
    0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb,
    0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa, 0x3fa, 0x3fb, 0xf9, 0xfb,
    0xfa, 0x16, 0x17, 0x18, 0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x5c, 0xfb, 0x7ffb, 0x7ffc, 0x7ffd, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x5c, 0xfb, 0x7ffb, 0x7ffc, 0x7ffd, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

static const uint8_t huff_nbits[256] = {
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 8, 8, 7, 7, 7,
    5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 15, 15, 6,
};

/* EOS symbol */
#define HUFF_EOS 256
#define HUFF_EOS_CODE 0x3fffffff
#define HUFF_EOS_BITS 30

/* Huffman encode a single string. Returns number of bytes written or 0 on failure. */
static size_t __attribute__((unused)) huffman_encode(const unsigned char *input, size_t input_len,
                              unsigned char *output, size_t output_size) {
    uint64_t bits = 0;
    int bits_left = 40;
    size_t out_pos = 0;

    for (size_t i = 0; i < input_len; i++) {
        uint8_t c = input[i];
        uint32_t code = huff_sym[c];
        uint8_t nbits = huff_nbits[c];
        bits = (bits << nbits) | code;
        bits_left -= nbits;
        while (bits_left <= 32) {
            if (out_pos >= output_size) return 0;
            output[out_pos++] = (unsigned char)(bits >> (bits_left > 0 ? bits_left : 0));
            bits_left += 8;
        }
    }

    if (bits_left < 40) {
        bits = (bits << bits_left) | (((uint64_t)1 << bits_left) - 1);
        bits_left = 0;
        while (bits_left < 40) {
            if (out_pos >= output_size) return 0;
            output[out_pos++] = (unsigned char)(bits >> (40 - 8));
            bits <<= 8;
            bits_left += 8;
        }
    }

    (void)HUFF_EOS;
    (void)HUFF_EOS_CODE;
    (void)HUFF_EOS_BITS;
    return out_pos;
}

/* Huffman decode node */
#define HUFF_NODE_TERMINAL 0x80000000

struct huff_node {
    uint32_t child[2];
};

static struct huff_node *huff_tree = NULL;
static int huff_tree_alloc = 0;

static int huff_tree_init(void) {
    if (huff_tree != NULL) return 0;
    huff_tree_alloc = 512;
    huff_tree = calloc((size_t)huff_tree_alloc, sizeof(struct huff_node));
    if (huff_tree == NULL) return -1;

    int node_count = 1;
    for (int sym = 0; sym < 256; sym++) {
        uint32_t code = huff_sym[sym];
        int nbits = huff_nbits[sym];
        int node = 0;

        for (int b = nbits - 1; b >= 0; b--) {
            int bit = (code >> b) & 1;
            if (huff_tree[node].child[bit] == 0) {
                if (node_count >= huff_tree_alloc) {
                    huff_tree_alloc *= 2;
                    struct huff_node *tmp = realloc(huff_tree,
                                          (size_t)huff_tree_alloc * sizeof(struct huff_node));
                    if (tmp == NULL) return -1;
                    huff_tree = tmp;
                    memset(&huff_tree[node_count], 0,
                           (size_t)(huff_tree_alloc - node_count) * sizeof(struct huff_node));
                }
                huff_tree[node].child[bit] = (uint32_t)node_count | HUFF_NODE_TERMINAL;
                node_count++;
            }
            node = (int)(huff_tree[node].child[bit] & ~HUFF_NODE_TERMINAL);
            if (b == 0) {
                huff_tree[node].child[bit] = (uint32_t)node | HUFF_NODE_TERMINAL;
            }
        }
    }
    return 0;
}

/* Returns number of decoded bytes or 0 on failure */
static size_t huffman_decode(const unsigned char *input, size_t input_len,
                              unsigned char *output, size_t output_size) {
    if (huff_tree_init() != 0) return 0;

    int node = 0;
    size_t out_pos = 0;

    for (size_t i = 0; i < input_len; i++) {
        for (int b = 7; b >= 0; b--) {
            int bit = (input[i] >> b) & 1;
            uint32_t child = huff_tree[node].child[bit];
            if (child == 0) return 0;
            node = (int)(child & ~HUFF_NODE_TERMINAL);
            if (child & HUFF_NODE_TERMINAL) {
                if (node == HUFF_EOS) return 0;
                if (out_pos < output_size) {
                    output[out_pos++] = (unsigned char)node;
                } else {
                    return 0;
                }
                node = 0;
            }
        }
    }

    if (node != 0) return 0;
    return out_pos;
}

static size_t hpack_encode_string(unsigned char *out, size_t out_size,
                                   const char *str, size_t str_len) {
    size_t off = 0;
    if (out_size < 1) return 0;
    out[off] = 0x00;
    size_t n = hpack_encode_int(out, out_size, (uint64_t)str_len, 7);
    if (n == 0) return 0;
    off = n;
    if (off + str_len > out_size) return 0;
    memcpy(out + off, str, str_len);
    off += str_len;
    return off;
}

static int hpack_decode_string(const unsigned char *buf, size_t buf_len,
                                size_t *offset, char *out, size_t out_size,
                                size_t *out_len) {
    if (*offset >= buf_len) return -1;
    bool huffman = (buf[*offset] & 0x80) != 0;

    uint64_t len64;
    if (hpack_decode_int(buf, buf_len, offset, 7, &len64) != 0)
        return -1;
    if (len64 > buf_len - *offset) return -1;
    size_t slen = (size_t)len64;

    if (huffman) {
        if (huffman_decode(buf + *offset, slen, (unsigned char *)out, out_size) == 0)
            return -1;
        *out_len = strlen(out);
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

static int get_table_entry(int index, const char **name, size_t *name_len,
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
    if (dyn_idx >= 0 && (size_t)dyn_idx < h2_dyn_table.count) {
        struct h2_hpack_entry *e = &h2_dyn_table.entries[dyn_idx];
        *name = e->name;
        *name_len = e->name_len;
        *value = e->value;
        *value_len = e->value_len;
        return 0;
    }
    return -1;
}

int http2_init_connection(struct connection *conn, char *error, size_t error_len) {
    memset(&h2_conn_state, 0, sizeof(h2_conn_state));
    h2_conn_state.conn_window = H2_DEFAULT_WINDOW;
    h2_conn_state.max_frame_size = H2_DEFAULT_MAX_FRAME_SIZE;
    h2_conn_state.initial_window_size = H2_DEFAULT_WINDOW;
    h2_conn_state.header_table_size = H2_MAX_DYNAMIC_TABLE_SIZE;
    h2_conn_state.last_stream_id = (uint32_t)-1; /* first +=2 gives 1 */

    hpack_table_init();

    if (conn_write(conn, H2_CLIENT_PREFACE, strlen(H2_CLIENT_PREFACE),
                   error, error_len) != 0)
        return -1;

    if (send_empty_settings(conn, error, error_len) != 0)
        return -1;

    /* Read frames until we get the server SETTINGS + optional ACK */
    bool got_settings = false;
    bool acked_our_settings = false;
    int max_reads = 10;

    while ((!got_settings || !acked_our_settings) && max_reads-- > 0) {
        unsigned char header[H2_FRAME_HEADER_SIZE];
        if (conn_read(conn, (char *)header, sizeof(header), error, error_len) != 0)
            return -1;

        size_t length = read24(header);
        uint8_t type = header[3];
        uint8_t flags = header[4];

        if (length > h2_conn_state.max_frame_size) {
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
            unsigned char *p = (unsigned char *)payload;
            for (size_t off = 0; off + 6 <= length; off += 6) {
                uint16_t id = (uint16_t)(p[off] << 8) | p[off + 1];
                uint32_t val = (uint32_t)(p[off + 2] << 24) | (p[off + 3] << 16) |
                               (p[off + 4] << 8) | p[off + 5];
                switch (id) {
                    case H2_SETTINGS_HEADER_TABLE_SIZE:
                        h2_conn_state.header_table_size = val;
                        hpack_table_set_max_size(val);
                        break;
                    case H2_SETTINGS_INITIAL_WINDOW_SIZE:
                        if (val > 2147483647u) {
                            free(payload);
                            set_error(error, error_len, "Invalid initial window size");
                            return -1;
                        }
                        h2_conn_state.initial_window_size = val;
                        break;
                    case H2_SETTINGS_MAX_FRAME_SIZE_ID:
                        if (val < 16384 || val > 16777215) {
                            free(payload);
                            set_error(error, error_len, "Invalid max frame size");
                            return -1;
                        }
                        h2_conn_state.max_frame_size = val;
                        break;
                }
            }
            if (send_settings_ack(conn, error, error_len) != 0) {
                free(payload);
                return -1;
            }
            h2_conn_state.settings_received = true;
        } else if (type == H2_SETTINGS && (flags & H2_FLAG_SETTINGS_ACK)) {
            acked_our_settings = true;
        } else if (type == H2_WINDOW_UPDATE && length >= 4) {
            uint32_t inc = (uint32_t)((unsigned char)payload[0] << 24) |
                          (uint32_t)((unsigned char)payload[1] << 16) |
                          (uint32_t)((unsigned char)payload[2] << 8) |
                          (unsigned char)payload[3];
            h2_conn_state.conn_window += (int32_t)inc;
        } else if (type == H2_PING && !(flags & 0x1)) {
            send_ping_ack(conn, payload, error, error_len);
        }

        free(payload);
    }

    if (!got_settings) {
        set_error(error, error_len, "HTTP/2 never received server SETTINGS");
        return -1;
    }

    /* Increase connection flow control window to avoid stalling on large responses */
    if (h2_conn_state.conn_window < 1048576) {
        uint32_t inc = 1048576 - (uint32_t)h2_conn_state.conn_window;
        send_window_update(conn, 0, inc, error, error_len);
        h2_conn_state.conn_window += (int32_t)inc;
    }

    return 0;
}

int http2_send_request(struct connection *conn, const struct url_info *url,
                       const char *method, const char *data, size_t data_len,
                       const char **extra_headers, size_t extra_header_count,
                       const char *user_agent, const char *basic_auth,
                       char *error, size_t error_len) {
    (void)error;
    (void)error_len;
    if (user_agent == NULL) user_agent = "curldbg/1.0";

    h2_conn_state.last_stream_id += 2;
    uint32_t stream_id = h2_conn_state.last_stream_id;

    const char *scheme = url->use_tls ? "https" : "http";
    char host_header[320];
    if (format_host_header(url, host_header, sizeof(host_header)) != 0) {
        set_error(error, error_len, "Host header too large");
        return -1;
    }

    /* HPACK-encode the pseudo-headers and regular headers */
    unsigned char block[65536];
    size_t block_len = 0;
    int n;

    n = hpack_encode_literal_with_indexing(block, sizeof(block), 0,
                                            ":method", 7, method, strlen(method));
    if (n < 0) { set_error(error, error_len, "HPACK encode failed"); return -1; }
    block_len = (size_t)n;

    n = hpack_encode_literal_with_indexing(block + block_len, sizeof(block) - block_len, 0,
                                            ":scheme", 7, scheme, strlen(scheme));
    if (n < 0) { set_error(error, error_len, "HPACK encode failed"); return -1; }
    block_len += (size_t)n;

    n = hpack_encode_literal_with_indexing(block + block_len, sizeof(block) - block_len, 0,
                                            ":authority", 10, host_header, strlen(host_header));
    if (n < 0) { set_error(error, error_len, "HPACK encode failed"); return -1; }
    block_len += (size_t)n;

    n = hpack_encode_literal_without_indexing(block + block_len, sizeof(block) - block_len, 0,
                                               ":path", 5, url->path, strlen(url->path));
    if (n < 0) { set_error(error, error_len, "HPACK encode failed"); return -1; }
    block_len += (size_t)n;

    /* User-Agent */
    n = hpack_encode_literal_without_indexing(block + block_len, sizeof(block) - block_len, 0,
                                               "user-agent", 10, user_agent, strlen(user_agent));
    if (n < 0) { set_error(error, error_len, "HPACK encode failed"); return -1; }
    block_len += (size_t)n;

    /* Authorization */
    if (basic_auth != NULL && basic_auth[0] != '\0') {
        char auth_b64[512];
        char auth_header[1024];
        if (base64_encode((const unsigned char *)basic_auth, strlen(basic_auth),
                           auth_b64, sizeof(auth_b64)) != 0) {
            set_error(error, error_len, "Basic auth value too large");
            return -1;
        }
        int na = snprintf(auth_header, sizeof(auth_header), "Basic %s", auth_b64);
        if (na < 0 || (size_t)na >= sizeof(auth_header)) {
            set_error(error, error_len, "Authorization header too large");
            return -1;
        }
        n = hpack_encode_literal_without_indexing(block + block_len, sizeof(block) - block_len,
                                                   0, "authorization", 13,
                                                   auth_header, (size_t)na);
        if (n < 0) { set_error(error, error_len, "HPACK encode failed"); return -1; }
        block_len += (size_t)n;
    }

    /* Extra headers */
    for (size_t i = 0; i < extra_header_count; i++) {
        if (extra_headers[i] == NULL) continue;
        const char *colon = strchr(extra_headers[i], ':');
        if (colon == NULL) continue;
        size_t name_len = (size_t)(colon - extra_headers[i]);
        const char *name = extra_headers[i];
        const char *val = colon + 1;
        while (*val == ' ' || *val == '\t') val++;
        size_t val_len = strlen(val);

        int name_idx = 0;
        lookup_static_name(name, name_len, &name_idx);

        n = hpack_encode_literal_without_indexing(block + block_len, sizeof(block) - block_len,
                                                   (uint64_t)name_idx,
                                                   name, name_len, val, val_len);
        if (n < 0) { set_error(error, error_len, "HPACK encode failed"); return -1; }
        block_len += (size_t)n;

        /* Add to dynamic table explicitly since we used without-indexing */
    }

    if (conn->verbose) {
        fprintf(stderr, "* Using HTTP/2 (stream %u)\n", stream_id);
        fprintf(stderr, "* Sending %zu bytes of HPACK-encoded headers\n", block_len);
    }

    bool end_stream = (data == NULL || data_len == 0);
    uint8_t flags = H2_FLAG_END_HEADERS | (end_stream ? H2_FLAG_END_STREAM : 0);

    size_t max_payload = h2_conn_state.max_frame_size;
    if (block_len <= max_payload) {
        if (send_frame_raw(conn, block_len, H2_HEADERS, flags, stream_id,
                           (char *)block, error, error_len) != 0)
            return -1;
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
                return -1;
            off += chunk;
            first = false;
        }
    }

    if (data != NULL && data_len > 0) {
        if (send_frame_raw(conn, data_len, H2_DATA, H2_FLAG_END_STREAM,
                           stream_id, data, error, error_len) != 0)
            return -1;
    }

    return 0;
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

int http2_receive_response(struct connection *conn, struct response_info *out,
                           const struct timespec *ttfb_start,
                           FILE *body_out, char *error, size_t error_len) {
    out->status_code = 0;
    out->content_length = -1;
    out->chunked = false;
    out->set_cookie_len = 0;
    out->set_cookie_buf[0] = '\0';
    out->content_encoding[0] = '\0';
    out->location[0] = '\0';
    out->preview_len = 0;
    out->ttfb_ms = -1.0;

    uint32_t stream_id = h2_conn_state.last_stream_id;
    bool stream_done = false;
    struct timespec first_byte_ts;
    bool seen_first_byte = false;

    while (!stream_done) {
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

        if (length > h2_conn_state.max_frame_size) {
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

        if (type == H2_SETTINGS) {
            if (!(flags & H2_FLAG_SETTINGS_ACK)) {
                /* Process server settings update */
                unsigned char *p = (unsigned char *)payload;
                for (size_t off = 0; off + 6 <= length; off += 6) {
                    uint16_t id = (uint16_t)(p[off] << 8) | p[off + 1];
                    uint32_t val = (uint32_t)(p[off + 2] << 24) | (p[off + 3] << 16) |
                                   (p[off + 4] << 8) | p[off + 5];
                    if (id == H2_SETTINGS_INITIAL_WINDOW_SIZE) {
                        if (val > 2147483647u) {
                            free(payload);
                            set_error(error, error_len, "Invalid initial window size");
                            return -1;
                        }
                        h2_conn_state.initial_window_size = val;
                    } else if (id == H2_SETTINGS_MAX_FRAME_SIZE_ID) {
                        if (val < 16384 || val > 16777215) {
                            free(payload);
                            set_error(error, error_len, "Invalid max frame size");
                            return -1;
                        }
                        h2_conn_state.max_frame_size = val;
                    } else if (id == H2_SETTINGS_HEADER_TABLE_SIZE) {
                        h2_conn_state.header_table_size = val;
                        hpack_table_set_max_size(val);
                    }
                }
                send_settings_ack(conn, error, error_len);
            }
            free(payload);
            continue;
        }

        if (type == H2_WINDOW_UPDATE) {
            if (length >= 4) {
                unsigned char *p = (unsigned char *)payload;
                uint32_t inc = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                               ((uint32_t)p[2] << 8) | p[3];
                if (fid == 0)
                    h2_conn_state.conn_window += (int32_t)inc;
            }
            free(payload);
            continue;
        }

        if (type == H2_PING) {
            if (!(flags & 0x1))
                send_ping_ack(conn, payload, error, error_len);
            free(payload);
            continue;
        }

        if (type == H2_GOAWAY) {
            free(payload);
            set_error(error, error_len, "HTTP/2 server sent GOAWAY");
            return -1;
        }

        if (type == H2_RST_STREAM) {
            if (fid == stream_id) {
                free(payload);
                set_error(error, error_len, "HTTP/2 stream was reset by server");
                return -1;
            }
            free(payload);
            continue;
        }

        if (type == H2_PUSH_PROMISE) {
            send_rst_stream(conn, fid, 0x8, error, error_len);
            free(payload);
            continue;
        }

        if (type == H2_PRIORITY) {
            free(payload);
            continue;
        }

        if (type == H2_HEADERS || type == H2_CONTINUATION) {
            if (fid != stream_id) {
                free(payload);
                continue;
            }

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

            if (!seen_first_byte && hpack_len > 0) {
                if (clock_gettime(CLOCK_MONOTONIC, &first_byte_ts) != 0) {
                    free(payload);
                    set_error(error, error_len, "clock_gettime failed");
                    return -1;
                }
                out->ttfb_ms = ms_between(ttfb_start, &first_byte_ts);
                seen_first_byte = true;
            }

            /* Decode HPACK block */
            size_t hpack_pos = 0;
            while (hpack_pos < hpack_len) {
                if (hpack_pos >= hpack_len) break;
                unsigned char b = (unsigned char)payload[hpack_off + hpack_pos];

                if ((b & 0x80) != 0) {
                    /* Indexed header */
                    uint64_t idx;
                    if (hpack_decode_int((const unsigned char *)payload + hpack_off,
                                         hpack_len, &hpack_pos, 7, &idx) != 0)
                        break;
                    const char *name, *value;
                    size_t name_len, value_len;
                    if (get_table_entry((int)idx, &name, &name_len,
                                        &value, &value_len) != 0)
                        break;
                    parse_h2_header(name, value, out);
                } else if ((b & 0x40) != 0) {
                    /* Literal with incremental indexing */
                    uint64_t name_idx;
                    if (hpack_decode_int((const unsigned char *)payload + hpack_off,
                                         hpack_len, &hpack_pos, 6, &name_idx) != 0)
                        break;

                    char name[256], value[4096];
                    size_t name_len = 0, value_len = 0;

                    if (name_idx == 0) {
                        if (hpack_decode_string((const unsigned char *)payload + hpack_off,
                                                 hpack_len, &hpack_pos,
                                                 name, sizeof(name), &name_len) != 0)
                            break;
                    } else {
                        const char *sn, *sv;
                        size_t sn_len, sv_len;
                        if (get_table_entry((int)name_idx, &sn, &sn_len,
                                            &sv, &sv_len) != 0)
                            break;
                        name_len = sn_len;
                        if (name_len >= sizeof(name)) break;
                        memcpy(name, sn, name_len);
                        name[name_len] = '\0';
                    }

                    if (hpack_decode_string((const unsigned char *)payload + hpack_off,
                                             hpack_len, &hpack_pos,
                                             value, sizeof(value), &value_len) != 0)
                        break;

                    hpack_table_add(name, name_len, value, value_len);
                    parse_h2_header(name, value, out);
                } else if ((b & 0x20) != 0) {
                    /* Dynamic table size update */
                    uint64_t new_size;
                    if (hpack_decode_int((const unsigned char *)payload + hpack_off,
                                         hpack_len, &hpack_pos, 5, &new_size) != 0)
                        break;
                    hpack_table_set_max_size((uint32_t)new_size);
                } else {
                    /* Literal without indexing / never indexed */
                    uint64_t name_idx;
                    if (hpack_decode_int((const unsigned char *)payload + hpack_off,
                                         hpack_len, &hpack_pos, 4, &name_idx) != 0)
                        break;

                    char name[256], value[4096];
                    size_t name_len = 0, value_len = 0;

                    if (name_idx == 0) {
                        if (hpack_decode_string((const unsigned char *)payload + hpack_off,
                                                 hpack_len, &hpack_pos,
                                                 name, sizeof(name), &name_len) != 0)
                            break;
                    } else {
                        const char *sn, *sv;
                        size_t sn_len, sv_len;
                        if (get_table_entry((int)name_idx, &sn, &sn_len,
                                            &sv, &sv_len) != 0)
                            break;
                        name_len = sn_len;
                        if (name_len >= sizeof(name)) break;
                        memcpy(name, sn, name_len);
                        name[name_len] = '\0';
                    }

                    if (hpack_decode_string((const unsigned char *)payload + hpack_off,
                                             hpack_len, &hpack_pos,
                                             value, sizeof(value), &value_len) != 0)
                        break;

                    parse_h2_header(name, value, out);
                }
            }

            if (flags & H2_FLAG_END_STREAM)
                stream_done = true;

            free(payload);
            continue;
        }

        if (type == H2_DATA) {
            if (fid != stream_id) {
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

            if (!seen_first_byte && data_len_actual > 0) {
                if (clock_gettime(CLOCK_MONOTONIC, &first_byte_ts) != 0) {
                    free(payload);
                    set_error(error, error_len, "clock_gettime failed");
                    return -1;
                }
                out->ttfb_ms = ms_between(ttfb_start, &first_byte_ts);
                seen_first_byte = true;
            }

            if (data_len_actual > 0) {
                const char *body_data = payload + data_off;
                if (body_out != NULL && fwrite(body_data, 1, data_len_actual, body_out) != data_len_actual) {
                    free(payload);
                    set_error(error, error_len, "Failed to write response body");
                    return -1;
                }
                if (out->preview_len < PREVIEW_BYTES) {
                    size_t take = data_len_actual;
                    if (take > PREVIEW_BYTES - out->preview_len)
                        take = PREVIEW_BYTES - out->preview_len;
                    memcpy(out->preview + out->preview_len, body_data, take);
                    out->preview_len += take;
                }

                /* Update flow control windows */
                send_window_update(conn, stream_id, (uint32_t)data_len_actual,
                                   error, error_len);
                send_window_update(conn, 0, (uint32_t)data_len_actual,
                                   error, error_len);
            }

            if (flags & H2_FLAG_END_STREAM)
                stream_done = true;

            free(payload);
            continue;
        }

        /* Unknown frame type - skip */
        free(payload);
    }

    out->preview[out->preview_len] = '\0';
    if (!seen_first_byte) out->ttfb_ms = -1.0;
    return 0;
}
