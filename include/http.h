#ifndef CURLDBG_HTTP_H
#define CURLDBG_HTTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>

#define PREVIEW_BYTES 1024
#define HEADER_MAX 16384
#define RESPONSE_READ_BUF 32768
#define RECV_BUF_SIZE 102400
#define UPLOAD_READ_BUF 32768

enum {
    HF_CONTENT_TYPE   = 1 << 0,
    HF_CONTENT_LENGTH = 1 << 1,
    HF_HOST           = 1 << 2,
    HF_ACCEPT_ENC     = 1 << 3,
    HF_USER_AGENT     = 1 << 4,
    HF_COOKIE         = 1 << 5,
    HF_REFERER        = 1 << 6,
};

struct response_info {
    char preview[PREVIEW_BYTES + 1];
    size_t preview_len;
    double ttfb_ms;
    int status_code;
    char location[2048];
    bool chunked;
    long content_length;
    char set_cookie_buf[4096];
    size_t set_cookie_len;
    char content_encoding[32];
    char header_text[HEADER_MAX + 1];
    char http_version[16];
};

struct connection;

bool is_redirect_status(int status_code);
void parse_response_headers(const char *headers, struct response_info *out);
int send_request(struct connection *conn, const struct url_info *url, const char *method,
                 const char *data, size_t data_len, FILE *upload_file, size_t upload_size,
                 const char **extra_headers, size_t extra_header_count,
                 const char *basic_auth, const char *user_agent,
                 char *error, size_t error_len, bool use_proxy, bool chunked_upload,
                 bool compressed, unsigned int header_flags);
int receive_response(struct connection *conn, const struct timespec *ttfb_start,
                     struct response_info *out, char *error, size_t error_len,
                     FILE *body_out, bool follow_redirects, bool fail_on_http_error, bool head_method);

#endif
