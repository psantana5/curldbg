#ifndef CURLDBG_HTTP2_INTERNAL_H
#define CURLDBG_HTTP2_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "curldbg.h"

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
    struct h2_stream *streams;
};

/* frame.c */
uint32_t read24(const unsigned char *p);
void write24(unsigned char *p, uint32_t v);
int send_frame_raw(struct connection *conn, size_t length, uint8_t type,
                   uint8_t flags, uint32_t stream_id,
                   const char *payload, char *error, size_t error_len);
int send_goaway(struct connection *conn, uint32_t last_stream_id,
                uint32_t error_code, char *error, size_t error_len);
int send_client_settings(struct connection *conn, char *error, size_t error_len);
int send_settings_ack(struct connection *conn, char *error, size_t error_len);
int send_window_update(struct connection *conn, uint32_t stream_id,
                       uint32_t increment, char *error, size_t error_len);
int send_rst_stream(struct connection *conn, uint32_t stream_id,
                    uint32_t error_code, char *error, size_t error_len);
int send_ping_ack(struct connection *conn, const char *data,
                  char *error, size_t error_len);

/* conn.c (I/O helpers) */
int conn_write(struct connection *conn, const char *buf, size_t len,
               char *error, size_t error_len);
int conn_readable(struct connection *conn, int timeout_ms);
int conn_read(struct connection *conn, char *buf, size_t len,
              char *error, size_t error_len);

/* settings.c */
int h2_settings_apply(struct h2_connection *h2,
                      const unsigned char *payload, size_t length,
                      char *error, size_t error_len);

/* stream.c */
struct h2_stream *stream_by_id(struct h2_connection *h2, uint32_t id);
struct h2_stream *alloc_stream(struct h2_connection *h2);
void free_stream(struct h2_connection *h2, struct h2_stream *s);
void flush_window_updates(struct connection *conn, struct h2_connection *h2,
                          char *error, size_t error_len);

/* dyn_table.c (HPACK dynamic table) */
void hpack_entry_free(struct h2_hpack_entry *e);
void hpack_table_evict(struct h2_hpack_table *dyn);
int hpack_table_add(struct h2_hpack_table *dyn, const char *name, size_t name_len,
                    const char *value, size_t value_len);
void hpack_table_set_max_size(struct h2_hpack_table *dyn, uint32_t new_size);
int get_table_entry(struct h2_hpack_table *dyn, int index,
                    const char **name, size_t *name_len,
                    const char **value, size_t *value_len);

/* headers.c */
int parse_h2_header_block(struct h2_connection *h2,
    struct h2_stream *dst, struct connection *conn, uint32_t fid,
    const unsigned char *block, size_t block_len,
    char *error, size_t error_len);

#endif
