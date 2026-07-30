#ifndef CURLDBG_CLI_H
#define CURLDBG_CLI_H

#include "net.h"

#define MAX_RESOLVE_ENTRIES 16
#define DEFAULT_MAX_REDIRECTS 10

struct cookie_jar;

struct cmdline_opts {
    char error[256];
    const char *input_url;
    const char *compare_url;
    char request_method[32];
    bool method_explicit;
    const char *request_data;
    size_t request_data_len;
    char *request_data_alloc;
    char *request_data_urlencode_alloc;
    bool compare_family_mode;
    bool compare_urls_mode;
    bool follow_redirects;
    bool fail_on_http_error;
    bool silent;
    bool show_error;
    const char *output_path;
    bool output_remote_name;
    bool insecure_tls;
    const char *basic_auth;
    const char *upload_path;
    const char **extra_headers;
    size_t extra_header_count;
    bool happy_eyeballs;
    bool verbose;
    const char *user_agent;
    const char *cookie_data;
    char *cookie_data_alloc;
    char *cookie_header_alloc;
    const char *cookie_jar_path;
    const char *cookie_file_to_load;
    const char *proxy_url;
    int address_family;
    int connect_timeout_ms;
    int read_timeout_ms;
    int max_time_ms;
    int max_redirects;
    struct resolve_entry resolve_entries[MAX_RESOLVE_ENTRIES];
    int resolve_count;
    const char *referer;
    const char *bind_interface;
    int tls_min_version;
    int tls_max_version;
    int retry_count;
    int retry_delay_ms;
    bool compressed;
    const char *unix_socket_path;
    const char *write_out_format;
    const char *cacert;
    const char *capath;
    const char **urls;
    int url_count;
    struct tls_params tls_params;
};

int parse_cmdline(int argc, char **argv, struct cmdline_opts *c);
void print_help(const char *prog);

#endif
