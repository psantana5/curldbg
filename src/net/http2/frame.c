#define _GNU_SOURCE
#include "http2_internal.h"

uint32_t read24(const unsigned char *p) {
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

void write24(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v >> 16);
    p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)v;
}

int send_frame_raw(struct connection *conn, size_t length, uint8_t type,
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

int send_goaway(struct connection *conn, uint32_t last_stream_id,
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

int send_client_settings(struct connection *conn, char *error, size_t error_len) {
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

int send_settings_ack(struct connection *conn, char *error, size_t error_len) {
    return send_frame_raw(conn, 0, H2_SETTINGS, H2_FLAG_SETTINGS_ACK, 0, NULL, error, error_len);
}

int send_window_update(struct connection *conn, uint32_t stream_id,
                       uint32_t increment, char *error, size_t error_len) {
    unsigned char payload[4];
    payload[0] = (unsigned char)(increment >> 24);
    payload[1] = (unsigned char)(increment >> 16);
    payload[2] = (unsigned char)(increment >> 8);
    payload[3] = (unsigned char)increment;
    return send_frame_raw(conn, 4, H2_WINDOW_UPDATE, 0, stream_id,
                          (char *)payload, error, error_len);
}

int send_rst_stream(struct connection *conn, uint32_t stream_id,
                    uint32_t error_code, char *error, size_t error_len) {
    unsigned char payload[4];
    payload[0] = (unsigned char)(error_code >> 24);
    payload[1] = (unsigned char)(error_code >> 16);
    payload[2] = (unsigned char)(error_code >> 8);
    payload[3] = (unsigned char)error_code;
    return send_frame_raw(conn, 4, H2_RST_STREAM, 0, stream_id,
                          (char *)payload, error, error_len);
}

int send_ping_ack(struct connection *conn, const char *data,
                  char *error, size_t error_len) {
    return send_frame_raw(conn, 8, H2_PING, 0x1, 0, data, error, error_len);
}
