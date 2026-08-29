#define _GNU_SOURCE
#include "http2_internal.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

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

/* Best-effort accumulation of the raw header block for --dump-header/-I/-v.
 * The parsed header fields remain authoritative; this mirrors the HTTP/1.1
 * path, which stores the raw status line + headers in header_text. */
static void h2_header_text_append(struct response_info *out,
                                  const char *name, const char *value) {
    size_t cur = strlen(out->header_text);
    size_t avail = sizeof(out->header_text) - cur;
    int n;
    if (avail < 3) return; /* buffer full: stop accumulating */
    if (name[0] == ':') {
        if (strcasecmp(name, ":status") != 0) return;
        n = snprintf(out->header_text + cur, avail, "HTTP/2 %s\r\n", value);
    } else {
        n = snprintf(out->header_text + cur, avail, "%s: %s\r\n", name, value);
    }
    if (n < 0 || (size_t)n >= avail)
        out->header_text[sizeof(out->header_text) - 1] = '\0';
}

static int apply_h2_header(const struct h2_connection *h2, struct h2_stream *dst,
    struct connection *conn, uint32_t fid,
    const char *name, const char *value,
    size_t name_len, size_t value_len,
    char *error, size_t error_len)
{
    if (dst->out) {
        if (name[0] == ':') {
            if (dst->trailers_pending || dst->saw_regular_header) {
                send_rst_stream(conn, fid, H2_PROTOCOL_ERROR, error, error_len);
                return 1;
            }
        } else {
            dst->saw_regular_header = true;
            for (const char *p = name; *p != '\0'; p++) {
                if (*p >= 'A' && *p <= 'Z') {
                    send_rst_stream(conn, fid, H2_PROTOCOL_ERROR, error, error_len);
                    return 1;
                }
            }
        }
        if (!dst->trailers_pending)
            h2_header_text_append(dst->out, name, value);
        parse_h2_header(name, value, dst->out);
    }
    dst->header_list_size += (uint32_t)(name_len + value_len + 32);
    if (h2->settings.max_header_list_size > 0 &&
        dst->header_list_size > h2->settings.max_header_list_size) {
        send_rst_stream(conn, fid, H2_ENHANCE_YOUR_CALM, error, error_len);
        return 1;
    }
    return 0;
}

static int decode_h2_header_name_value(const struct huff_node *tree,
    const unsigned char *block, size_t block_len, size_t *hp,
    struct h2_hpack_table *table, uint64_t name_idx,
    char *name, char *value, size_t *name_len, size_t *value_len)
{
    if (name_idx == 0) {
        if (hpack_decode_string(tree, block, block_len, hp, name, H2_MAX_HEADER_NAME_LEN, name_len) != 0)
            return -1;
    } else {
        const char *sn, *sv;
        size_t sn_len, sv_len;
        if (get_table_entry(table, (int)name_idx, &sn, &sn_len, &sv, &sv_len) != 0)
            return -1;
        *name_len = sn_len;
        if (*name_len >= H2_MAX_HEADER_NAME_LEN) return -1;
        memcpy(name, sn, *name_len);
        name[*name_len] = '\0';
    }
    if (hpack_decode_string(tree, block, block_len, hp, value, H2_MAX_HEADER_VALUE_LEN, value_len) != 0)
        return -1;
    return 0;
}

/*
 * Parse a single HPACK header block fragment.
 * Returns: 0 = OK, -1 = HPACK compression error (send GOAWAY), 1 = stream reset.
 */
int parse_h2_header_block(struct h2_connection *h2,
    struct h2_stream *dst, struct connection *conn, uint32_t fid,
    const unsigned char *block, size_t block_len,
    char *error, size_t error_len)
{
    size_t hp = 0;
    int rc;
    while (hp < block_len) {
        unsigned char b = block[hp];

        if ((b & 0x80) != 0) {
            uint64_t idx;
            if (hpack_decode_int(block, block_len, &hp, 7, &idx) != 0)
                return -1;
            const char *name, *value;
            size_t name_len, value_len;
            if (get_table_entry(&h2->dyn_table, (int)idx, &name, &name_len,
                                &value, &value_len) != 0)
                return -1;
            rc = apply_h2_header(h2, dst, conn, fid, name, value, name_len, value_len, error, error_len);
            if (rc != 0) return rc;
        } else if ((b & 0x40) != 0) {
            uint64_t name_idx;
            if (hpack_decode_int(block, block_len, &hp, 6, &name_idx) != 0)
                return -1;

            char name[H2_MAX_HEADER_NAME_LEN];
            char value[H2_MAX_HEADER_VALUE_LEN];
            size_t name_len = 0, value_len = 0;

            if (decode_h2_header_name_value(h2->huff_tree, block, block_len, &hp,
                                             &h2->dyn_table, name_idx,
                                             name, value, &name_len, &value_len) != 0)
                return -1;

            if (hpack_table_add(&h2->dyn_table, name, name_len, value, value_len) != 0)
                return -1;
            rc = apply_h2_header(h2, dst, conn, fid, name, value, name_len, value_len, error, error_len);
            if (rc != 0) return rc;
        } else if ((b & 0x20) != 0) {
            uint64_t new_size;
            if (hpack_decode_int(block, block_len, &hp, 5, &new_size) != 0)
                return -1;
            if (new_size > h2->settings.header_table_size)
                return -1;
            hpack_table_set_max_size(&h2->dyn_table, (uint32_t)new_size);
        } else {
            uint64_t name_idx;
            if (hpack_decode_int(block, block_len, &hp, 4, &name_idx) != 0)
                return -1;

            char name[H2_MAX_HEADER_NAME_LEN];
            char value[H2_MAX_HEADER_VALUE_LEN];
            size_t name_len = 0, value_len = 0;

            if (decode_h2_header_name_value(h2->huff_tree, block, block_len, &hp,
                                             &h2->dyn_table, name_idx,
                                             name, value, &name_len, &value_len) != 0)
                return -1;

            rc = apply_h2_header(h2, dst, conn, fid, name, value, name_len, value_len, error, error_len);
            if (rc != 0) return rc;
        }
    }
    return 0;
}
