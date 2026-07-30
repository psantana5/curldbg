#include "curldbg.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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

int lookup_static_name(const char *name, size_t name_len, int *idx_out) {
    for (int i = 1; i < 62; i++) {
        if (h2_static_table[i].name_len == name_len &&
            memcmp(h2_static_table[i].name, name, name_len) == 0) {
            *idx_out = i;
            return 0;
        }
    }
    return -1;
}

const struct h2_static_entry *get_static_entry(int idx) {
    if (idx >= 1 && idx < 62) return &h2_static_table[idx];
    return NULL;
}

size_t hpack_encode_int(unsigned char *out, size_t out_size,
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

int hpack_decode_int(const unsigned char *buf, size_t buf_len,
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

size_t hpack_encode_string(unsigned char *out, size_t out_size,
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

int hpack_decode_string(const struct huff_node *tree,
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
        size_t decoded = huffman_decode(tree, buf + *offset, slen,
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

int hpack_decode_string_ext(const struct huff_node *tree,
                             const unsigned char *buf, size_t buf_len,
                             size_t *offset, char *out, size_t out_size,
                             size_t *out_len) {
    return hpack_decode_string(tree, buf, buf_len, offset, out, out_size, out_len);
}

int hpack_encode_literal_with_indexing(unsigned char *out, size_t out_size,
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
