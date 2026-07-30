#ifndef CURLDBG_URL_H
#define CURLDBG_URL_H

#include <stdbool.h>
#include <stddef.h>

struct url_info {
    char host[256];
    char port[16];
    char path[1024];
    char user[256];
    char pass[256];
    bool use_tls;
    bool has_explicit_port;
};

int parse_url(const char *url, struct url_info *out);
int format_url(const struct url_info *url, char *out_url, size_t out_size);
int format_absolute_uri(const struct url_info *url, char *out, size_t out_size);
int format_host_header(const struct url_info *url, char *out, size_t out_size);
int build_redirect_url(const char *location, const struct url_info *base, char *out_url, size_t out_size);
int output_filename_from_url(const char *input_url, char *out, size_t out_size);

#endif
