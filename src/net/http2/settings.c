#define _GNU_SOURCE
#include "http2_internal.h"

/*
 * Parse and apply a SETTINGS frame payload (without the ACK flag).
 * Validates values and duplicate identifiers per RFC 7540 Section 6.5.
 * Returns 0 on success, -1 on a protocol error (error message set).
 */
int h2_settings_apply(struct h2_connection *h2,
                      const unsigned char *payload, size_t length,
                      char *error, size_t error_len) {
    const unsigned char *p = payload;
    for (size_t off = 0; off + 6 <= length; off += 6) {
        uint16_t id = (uint16_t)(p[off] << 8) | p[off + 1];
        for (size_t j = 0; j < off; j += 6) {
            uint16_t prev = (uint16_t)(p[j] << 8) | p[j + 1];
            if (prev == id) {
                set_error(error, error_len,
                    "Duplicate setting identifier in SETTINGS frame");
                return -1;
            }
        }
        uint32_t val = ((uint32_t)p[off + 2] << 24) | ((uint32_t)p[off + 3] << 16) |
                       ((uint32_t)p[off + 4] << 8) | (uint32_t)p[off + 5];

        if (id == H2_SETTINGS_HEADER_TABLE_SIZE) {
            if (val > H2_MAX_DYNAMIC_TABLE_SIZE)
                val = H2_MAX_DYNAMIC_TABLE_SIZE;
            h2->settings.header_table_size = val;
            hpack_table_set_max_size(&h2->dyn_table, val);
        } else if (id == H2_SETTINGS_INITIAL_WINDOW_SIZE) {
            if (val > 2147483647u) {
                set_error(error, error_len, "Invalid initial window size");
                return -1;
            }
            int32_t delta = (int32_t)val - (int32_t)h2->settings.initial_window_size;
            for (size_t i = 0; i < H2_MAX_STREAMS; i++) {
                if (h2->streams[i].active &&
                    (int32_t)(0x7FFFFFFF - h2->streams[i].window) < delta) {
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
                set_error(error, error_len, "Invalid max frame size");
                return -1;
            }
            h2->settings.max_frame_size = val;
        } else if (id == H2_SETTINGS_ENABLE_PUSH) {
            if (val > 1) {
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
    return 0;
}
