#ifndef CURLDBG_RUN_H
#define CURLDBG_RUN_H

#include "http.h"
#include "net.h"

#define WRITE_OUT_VAR_MAX 64

struct cmdline_opts;
struct cookie_jar;

struct hop_info {
    int status_code;
    char host[256];
    char redirect_to_host[256];
    char redirect_url[2048];
    bool has_redirect_target;
    double dns_ms;
    double tcp_ms;
    double ttfb_ms;
    char connected_ip[NI_MAXHOST];
    int connected_family;
    bool has_loser;
    char loser_ip[NI_MAXHOST];
    int loser_family;
    double loser_connect_ms;
    char content_type[128];
};

struct run_options {
    char method[32];
    const char *data;
    size_t data_len;
    bool follow_redirects;
    bool happy_eyeballs;
    bool verbose;
    bool insecure_tls;
    bool compressed;
    bool is_head_method;
    bool fail_on_http_error;
    int address_family;
    int connect_timeout_ms;
    int read_timeout_ms;
    int max_time_ms;
    int max_redirects;
    int tls_min_version;
    int tls_max_version;
    int retry_count;
    int retry_delay_ms;
    FILE *body_out;
    const char *basic_auth;
    const char **extra_headers;
    size_t extra_header_count;
    const char *upload_path;
    const char *user_agent;
    const char *proxy_host;
    const char *proxy_port;
    const char *cookie_data;
    const char *cookie_jar_path;
    struct cookie_jar *cookie_jar;
    const struct resolve_entry *resolve_entries;
    int resolve_count;
    const char *referer;
    const char *bind_interface;
    const char *unix_socket_path;
    const char *cacert;
    const char *capath;
    struct tls_params tls_params;
    SSL_CTX *tls_ctx;
    struct dns_cache *dns_cache;
};

struct run_result {
    struct response_info resp;
    struct hop_info *hops;
    int hop_count;
    double dns_ms;
    double connect_ms;
    double ttfb_ms;
    double total_ms;
    char final_url[2048];
    char error[256];
    bool is_head;
};

/* run.c */
int run_single_request(const struct cmdline_opts *c, struct run_options *opts,
                       struct run_result *result, FILE *body_out,
                       struct connection_state *reuse);
void init_run_options(struct run_options *opts, const struct cmdline_opts *c);
void run_two_requests_parallel(const char *url_a, const struct run_options *opts_a,
                               struct run_result *result_a, bool *ok_a,
                               const char *url_b, const struct run_options *opts_b,
                               struct run_result *result_b, bool *ok_b);
void free_run_result(struct run_result *result);

/* results.c */
void print_single_output(const struct run_result *result);
int final_status_code(const struct run_result *result);
void final_endpoint(const struct run_result *result, char *out, size_t out_size);
void print_compare_family_run(const char *name, const struct run_result *result, bool ok);
void print_compare_metric_row(const char *metric, double a, double b);
void print_compare_text_row(const char *metric, const char *a, const char *b);
void print_compare_family_metric(const char *label, double v4, double v6);

/* output.c */
void write_out_expand(const char *fmt, const struct run_result *result);

/* compare.c */
int run_compare_family(const struct cmdline_opts *c, struct run_options *opts);
int run_compare_urls(const struct cmdline_opts *c, struct run_options *opts);

#endif
