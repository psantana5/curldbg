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

#define HUFF_STATIC_NODES 256

static const struct huff_node huff_static_tree[HUFF_STATIC_NODES] = {
    {{ 0x00000042u, 0x00000001u }},
    {{ 0x0000005du, 0x00000002u }},
    {{ 0x00000068u, 0x00000003u }},
    {{ 0x00000077u, 0x00000004u }},
    {{ 0x00000090u, 0x00000005u }},
    {{ 0x0000004bu, 0x00000006u }},
    {{ 0x0000007bu, 0x00000007u }},
    {{ 0x00000047u, 0x00000008u }},
    {{ 0x0000004du, 0x00000009u }},
    {{ 0x00000049u, 0x0000000au }},
    {{ 0x0000000bu, 0x0000000du }},
    {{ 0x0000000cu, 0x00000066u }},
    {{ 0x80000000u, 0x80000024u }},
    {{ 0x0000007fu, 0x0000000eu }},
    {{ 0x00000080u, 0x0000000fu }},
    {{ 0x00000062u, 0x00000010u }},
    {{ 0x8000007bu, 0x00000011u }},
    {{ 0x0000007cu, 0x00000012u }},
    {{ 0x00000096u, 0x00000013u }},
    {{ 0x00000014u, 0x00000019u }},
    {{ 0x000000c7u, 0x00000015u }},
    {{ 0x000000d8u, 0x00000016u }},
    {{ 0x00000017u, 0x000000a2u }},
    {{ 0x00000018u, 0x000000a1u }},
    {{ 0x80000001u, 0x80000087u }},
    {{ 0x000000a7u, 0x0000001au }},
    {{ 0x00000029u, 0x0000001bu }},
    {{ 0x000000bfu, 0x0000001cu }},
    {{ 0x000000d3u, 0x0000001du }},
    {{ 0x000000e5u, 0x0000001eu }},
    {{ 0x0000001fu, 0x0000002du }},
    {{ 0x00000020u, 0x00000026u }},
    {{ 0x00000021u, 0x00000023u }},
    {{ 0x800000feu, 0x00000022u }},
    {{ 0x80000002u, 0x80000003u }},
    {{ 0x00000024u, 0x00000025u }},
    {{ 0x80000004u, 0x80000005u }},
    {{ 0x80000006u, 0x80000007u }},
    {{ 0x00000027u, 0x00000034u }},
    {{ 0x00000028u, 0x00000033u }},
    {{ 0x80000008u, 0x8000000bu }},
    {{ 0x000000d0u, 0x0000002au }},
    {{ 0x0000002bu, 0x000000a5u }},
    {{ 0x800000efu, 0x0000002cu }},
    {{ 0x80000009u, 0x8000008eu }},
    {{ 0x00000037u, 0x0000002eu }},
    {{ 0x0000003fu, 0x0000002fu }},
    {{ 0x00000093u, 0x00000030u }},
    {{ 0x800000f9u, 0x00000031u }},
    {{ 0x00000032u, 0x0000003bu }},
    {{ 0x8000000au, 0x8000000du }},
    {{ 0x8000000cu, 0x8000000eu }},
    {{ 0x00000035u, 0x00000036u }},
    {{ 0x8000000fu, 0x80000010u }},
    {{ 0x80000011u, 0x80000012u }},
    {{ 0x00000038u, 0x0000003cu }},
    {{ 0x00000039u, 0x0000003au }},
    {{ 0x80000013u, 0x80000014u }},
    {{ 0x80000015u, 0x80000017u }},
    {{ 0x80000016u, 0x00000000u }},
    {{ 0x0000003du, 0x0000003eu }},
    {{ 0x80000018u, 0x80000019u }},
    {{ 0x8000001au, 0x8000001bu }},
    {{ 0x00000040u, 0x00000041u }},
    {{ 0x8000001cu, 0x8000001du }},
    {{ 0x8000001eu, 0x8000001fu }},
    {{ 0x00000055u, 0x00000043u }},
    {{ 0x00000044u, 0x00000052u }},
    {{ 0x0000008fu, 0x00000045u }},
    {{ 0x00000046u, 0x00000051u }},
    {{ 0x80000020u, 0x80000025u }},
    {{ 0x00000048u, 0x0000004fu }},
    {{ 0x80000021u, 0x80000022u }},
    {{ 0x8000007cu, 0x0000004au }},
    {{ 0x80000023u, 0x8000003eu }},
    {{ 0x0000004cu, 0x00000050u }},
    {{ 0x80000026u, 0x8000002au }},
    {{ 0x8000003fu, 0x0000004eu }},
    {{ 0x80000027u, 0x8000002bu }},
    {{ 0x80000028u, 0x80000029u }},
    {{ 0x8000002cu, 0x8000003bu }},
    {{ 0x8000002du, 0x8000002eu }},
    {{ 0x00000053u, 0x0000005au }},
    {{ 0x00000054u, 0x00000059u }},
    {{ 0x8000002fu, 0x80000033u }},
    {{ 0x00000056u, 0x00000082u }},
    {{ 0x00000057u, 0x00000058u }},
    {{ 0x80000030u, 0x80000031u }},
    {{ 0x80000032u, 0x80000061u }},
    {{ 0x80000034u, 0x80000035u }},
    {{ 0x0000005bu, 0x0000005cu }},
    {{ 0x80000036u, 0x80000037u }},
    {{ 0x80000038u, 0x80000039u }},
    {{ 0x00000063u, 0x0000005eu }},
    {{ 0x0000008au, 0x0000005fu }},
    {{ 0x0000008eu, 0x00000060u }},
    {{ 0x00000061u, 0x00000067u }},
    {{ 0x8000003au, 0x80000042u }},
    {{ 0x8000003cu, 0x80000060u }},
    {{ 0x00000064u, 0x00000084u }},
    {{ 0x00000065u, 0x00000081u }},
    {{ 0x8000003du, 0x80000041u }},
    {{ 0x80000040u, 0x8000005bu }},
    {{ 0x80000043u, 0x80000044u }},
    {{ 0x00000069u, 0x00000070u }},
    {{ 0x0000006au, 0x0000006du }},
    {{ 0x0000006bu, 0x0000006cu }},
    {{ 0x80000045u, 0x80000046u }},
    {{ 0x80000047u, 0x80000048u }},
    {{ 0x0000006eu, 0x0000006fu }},
    {{ 0x80000049u, 0x8000004au }},
    {{ 0x8000004bu, 0x8000004cu }},
    {{ 0x00000071u, 0x00000074u }},
    {{ 0x00000072u, 0x00000073u }},
    {{ 0x8000004du, 0x8000004eu }},
    {{ 0x8000004fu, 0x80000050u }},
    {{ 0x00000075u, 0x00000076u }},
    {{ 0x80000051u, 0x80000052u }},
    {{ 0x80000053u, 0x80000054u }},
    {{ 0x00000078u, 0x00000088u }},
    {{ 0x00000079u, 0x0000007au }},
    {{ 0x80000055u, 0x80000056u }},
    {{ 0x80000057u, 0x80000059u }},
    {{ 0x80000058u, 0x8000005au }},
    {{ 0x0000007du, 0x0000009bu }},
    {{ 0x0000007eu, 0x00000094u }},
    {{ 0x8000005cu, 0x800000c3u }},
    {{ 0x8000005du, 0x8000007eu }},
    {{ 0x8000005eu, 0x8000007du }},
    {{ 0x8000005fu, 0x80000062u }},
    {{ 0x00000083u, 0x00000087u }},
    {{ 0x80000063u, 0x80000065u }},
    {{ 0x00000085u, 0x00000086u }},
    {{ 0x80000064u, 0x80000066u }},
    {{ 0x80000067u, 0x80000068u }},
    {{ 0x80000069u, 0x8000006fu }},
    {{ 0x00000089u, 0x0000008du }},
    {{ 0x8000006au, 0x8000006bu }},
    {{ 0x0000008bu, 0x0000008cu }},
    {{ 0x8000006cu, 0x8000006du }},
    {{ 0x8000006eu, 0x80000070u }},
    {{ 0x80000071u, 0x80000076u }},
    {{ 0x80000072u, 0x80000075u }},
    {{ 0x80000073u, 0x80000074u }},
    {{ 0x00000091u, 0x00000092u }},
    {{ 0x80000077u, 0x80000078u }},
    {{ 0x80000079u, 0x8000007au }},
    {{ 0x8000007fu, 0x800000dcu }},
    {{ 0x800000d0u, 0x00000095u }},
    {{ 0x80000080u, 0x80000082u }},
    {{ 0x000000c4u, 0x00000097u }},
    {{ 0x00000098u, 0x000000b2u }},
    {{ 0x00000099u, 0x0000009eu }},
    {{ 0x800000e6u, 0x0000009au }},
    {{ 0x80000081u, 0x80000084u }},
    {{ 0x0000009cu, 0x000000afu }},
    {{ 0x0000009du, 0x000000ccu }},
    {{ 0x80000083u, 0x800000a2u }},
    {{ 0x0000009fu, 0x000000a0u }},
    {{ 0x80000085u, 0x80000086u }},
    {{ 0x80000088u, 0x80000092u }},
    {{ 0x80000089u, 0x8000008au }},
    {{ 0x000000a3u, 0x000000a4u }},
    {{ 0x8000008bu, 0x8000008cu }},
    {{ 0x8000008du, 0x8000008fu }},
    {{ 0x000000a6u, 0x000000abu }},
    {{ 0x80000090u, 0x80000091u }},
    {{ 0x000000a8u, 0x000000b9u }},
    {{ 0x000000a9u, 0x000000adu }},
    {{ 0x000000aau, 0x000000acu }},
    {{ 0x80000093u, 0x80000095u }},
    {{ 0x80000094u, 0x8000009fu }},
    {{ 0x80000096u, 0x80000097u }},
    {{ 0x000000aeu, 0x000000b5u }},
    {{ 0x80000098u, 0x8000009bu }},
    {{ 0x000000f1u, 0x000000b0u }},
    {{ 0x000000b1u, 0x000000bcu }},
    {{ 0x80000099u, 0x800000a1u }},
    {{ 0x000000b3u, 0x000000b7u }},
    {{ 0x000000b4u, 0x000000b6u }},
    {{ 0x8000009au, 0x8000009cu }},
    {{ 0x8000009du, 0x8000009eu }},
    {{ 0x800000a0u, 0x800000a3u }},
    {{ 0x000000b8u, 0x000000beu }},
    {{ 0x800000a4u, 0x800000a9u }},
    {{ 0x000000bau, 0x000000c2u }},
    {{ 0x000000bbu, 0x000000bdu }},
    {{ 0x800000a5u, 0x800000a6u }},
    {{ 0x800000a7u, 0x800000acu }},
    {{ 0x800000a8u, 0x800000aeu }},
    {{ 0x800000aau, 0x800000adu }},
    {{ 0x000000c0u, 0x000000dau }},
    {{ 0x000000c1u, 0x000000eau }},
    {{ 0x800000abu, 0x800000ceu }},
    {{ 0x000000c3u, 0x000000cbu }},
    {{ 0x800000afu, 0x800000b4u }},
    {{ 0x000000c5u, 0x000000ebu }},
    {{ 0x000000c6u, 0x000000cau }},
    {{ 0x800000b0u, 0x800000b1u }},
    {{ 0x000000c8u, 0x000000ceu }},
    {{ 0x000000c9u, 0x000000cdu }},
    {{ 0x800000b2u, 0x800000b5u }},
    {{ 0x800000b3u, 0x800000d1u }},
    {{ 0x800000b6u, 0x800000b7u }},
    {{ 0x800000b8u, 0x800000c2u }},
    {{ 0x800000b9u, 0x800000bau }},
    {{ 0x000000cfu, 0x000000d2u }},
    {{ 0x800000bbu, 0x800000bdu }},
    {{ 0x000000d1u, 0x000000d7u }},
    {{ 0x800000bcu, 0x800000bfu }},
    {{ 0x800000beu, 0x800000c4u }},
    {{ 0x000000d4u, 0x000000e0u }},
    {{ 0x000000d5u, 0x000000deu }},
    {{ 0x000000d6u, 0x000000ddu }},
    {{ 0x800000c0u, 0x800000c1u }},
    {{ 0x800000c5u, 0x800000e7u }},
    {{ 0x000000d9u, 0x000000f3u }},
    {{ 0x800000c6u, 0x800000e4u }},
    {{ 0x000000f5u, 0x000000dbu }},
    {{ 0x000000dcu, 0x000000f4u }},
    {{ 0x800000c7u, 0x800000cfu }},
    {{ 0x800000c8u, 0x800000c9u }},
    {{ 0x000000dfu, 0x000000e4u }},
    {{ 0x800000cau, 0x800000cdu }},
    {{ 0x000000edu, 0x000000e1u }},
    {{ 0x000000f8u, 0x000000e2u }},
    {{ 0x800000ffu, 0x000000e3u }},
    {{ 0x800000cbu, 0x800000ccu }},
    {{ 0x800000d2u, 0x800000d5u }},
    {{ 0x000000e6u, 0x000000f9u }},
    {{ 0x000000e7u, 0x000000efu }},
    {{ 0x000000e8u, 0x000000e9u }},
    {{ 0x800000d3u, 0x800000d4u }},
    {{ 0x800000d6u, 0x800000ddu }},
    {{ 0x800000d7u, 0x800000e1u }},
    {{ 0x000000ecu, 0x000000f2u }},
    {{ 0x800000d8u, 0x800000d9u }},
    {{ 0x000000eeu, 0x000000f6u }},
    {{ 0x800000dau, 0x800000dbu }},
    {{ 0x000000f0u, 0x000000f7u }},
    {{ 0x800000deu, 0x800000dfu }},
    {{ 0x800000e0u, 0x800000e2u }},
    {{ 0x800000e3u, 0x800000e5u }},
    {{ 0x800000e8u, 0x800000e9u }},
    {{ 0x800000eau, 0x800000ebu }},
    {{ 0x800000ecu, 0x800000edu }},
    {{ 0x800000eeu, 0x800000f0u }},
    {{ 0x800000f1u, 0x800000f4u }},
    {{ 0x800000f2u, 0x800000f3u }},
    {{ 0x000000fau, 0x000000fdu }},
    {{ 0x000000fbu, 0x000000fcu }},
    {{ 0x800000f5u, 0x800000f6u }},
    {{ 0x800000f7u, 0x800000f8u }},
    {{ 0x000000feu, 0x000000ffu }},
    {{ 0x800000fau, 0x800000fbu }},
    {{ 0x800000fcu, 0x800000fdu }}
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
	(void)alloc;
	*tree = (struct huff_node *)huff_static_tree;
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
        if (decoded >= out_size || (decoded == 0 && slen > 0)) return -1;
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
    if (out_size < 1) return -1;
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

int hpack_encode_literal_without_indexing(unsigned char *out, size_t out_size,
                                          uint64_t name_index,
                                          const char *name, size_t name_len,
                                          const char *value, size_t value_len) {
    if (out_size < 1) return -1;
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
