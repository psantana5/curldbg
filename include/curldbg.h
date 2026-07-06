#ifndef CURLDBG_H
#define CURLDBG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>

#define MAX_RESOLVE_ENTRIES 16
#define PREVIEW_BYTES 1024
#define HEADER_MAX 16384
#define RESPONSE_READ_BUF 32768
#define RECV_BUF_SIZE 102400
#define UPLOAD_READ_BUF 32768
#define DEFAULT_MAX_REDIRECTS 10
#define MAX_COOKIES 256
#define MAX_COOKIE_LEN 4096
#define WRITE_OUT_VAR_MAX 64
#define CURLDBG_VERSION "1.2.0"

enum {
    HF_CONTENT_TYPE   = 1 << 0,
    HF_CONTENT_LENGTH = 1 << 1,
    HF_HOST           = 1 << 2,
    HF_ACCEPT_ENC     = 1 << 3,
    HF_USER_AGENT     = 1 << 4,
    HF_COOKIE         = 1 << 5,
    HF_REFERER        = 1 << 6,
};

struct tls_params {
    const char *cacert;
    const char *capath;
};

struct resolve_entry {
    char host[256];
    char port[16];
    struct sockaddr_storage ss;
    socklen_t ss_len;
    int family;
};

struct url_info {
    char host[256];
    char port[16];
    char path[1024];
    char user[256];
    char pass[256];
    bool use_tls;
    bool has_explicit_port;
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
};

struct cookie_entry {
    char domain[256];
    bool include_subdomains;
    char path[1024];
    char name[256];
    char value[4096];
    bool secure;
};

struct cookie_jar {
    struct cookie_entry entries[MAX_COOKIES];
    int count;
};

struct hop_info {
    int status_code;
    char host[256];
    char redirect_to_host[256];
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

struct connect_race_info {
    double winner_connect_ms;
    bool has_loser;
    char loser_ip[NI_MAXHOST];
    int loser_family;
    double loser_connect_ms;
};

struct connection {
    int fd;
    bool use_tls;
    SSL_CTX *ctx;
    SSL *ssl;
    bool verbose;
};

struct connection_state {
    struct connection conn;
    char host[256];
    char port[16];
    bool use_tls;
    struct addrinfo *addrs;
};

struct run_options {
    char method[32];
    const char *data;
    size_t data_len;
    bool follow_redirects;
    int address_family;
    int connect_timeout_ms;
    int read_timeout_ms;
    int max_time_ms;
    int max_redirects;
    bool fail_on_http_error;
    FILE *body_out;
    bool insecure_tls;
    const char *basic_auth;
    const char **extra_headers;
    size_t extra_header_count;
    const char *upload_path;
    bool happy_eyeballs;
    bool verbose;
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
    int tls_min_version;
    int tls_max_version;
    int retry_count;
    int retry_delay_ms;
    bool compressed;
    const char *unix_socket_path;
    bool is_head_method;
};

struct run_result {
    struct hop_info *hops;
    int hop_count;
    struct response_info resp;
    double dns_ms;
    double connect_ms;
    double ttfb_ms;
    double total_ms;
    char final_url[2048];
    char error[256];
};

struct cmdline_opts {
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
    bool wizard_mode;
    bool debug_chaos;
    bool lore_mode;
    bool fika_mode;
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
};

extern struct tls_params g_tls_params;

/* --- cli.c --- */
void parse_cmdline(int argc, char **argv, struct cmdline_opts *c);

/* --- request.c --- */
int run_single_request(const struct cmdline_opts *c, struct run_options *opts,
                       struct run_result *result, FILE *body_out,
                       struct connection_state *reuse);
void init_run_options(struct run_options *opts, const struct cmdline_opts *c);
void run_two_requests_parallel(const char *url_a, const struct run_options *opts_a,
                               struct run_result *result_a, bool *ok_a,
                               const char *url_b, const struct run_options *opts_b,
                               struct run_result *result_b, bool *ok_b);
void free_run_result(struct run_result *result);

/* --- results.c --- */
void print_single_output(const struct run_result *result);
int final_status_code(const struct run_result *result);
void final_endpoint(const struct run_result *result, char *out, size_t out_size);
void print_compare_family_run(const char *name, const struct run_result *result, bool ok);
void print_compare_metric_row(const char *metric, double a, double b);
void print_compare_text_row(const char *metric, const char *a, const char *b);
void print_compare_family_metric(const char *label, double v4, double v6);

/* --- output.c --- */
void write_out_expand(const char *fmt, const struct run_result *result);

/* --- util.c --- */
void die(const char *msg);
void set_error(char *error, size_t error_len, const char *fmt, ...);
int url_encode(const char *input, char *output, size_t output_size);
void set_ssl_error(char *error, size_t error_len, const char *prefix);
double ms_between(const struct timespec *start, const struct timespec *end);
const char *family_name(int family);
int base64_encode(const unsigned char *input, size_t len, char *out, size_t out_len);
int append_str(char *buf, size_t buf_size, size_t *offset, const char *str);
bool is_timeout_errno(int err);
long long now_ms_monotonic(void);
int set_nonblocking(int fd, bool enabled);
void fill_connected_endpoint(const struct addrinfo *ai, char *connected_ip, size_t connected_ip_size, int *connected_family);
void clear_race_info(struct connect_race_info *race_info);
void trim_spaces(char **start);
long deadline_remaining_ms(const struct timespec *start, int max_ms);

/* --- url.c --- */
int parse_url(const char *url, struct url_info *out);
int format_url(const struct url_info *url, char *out_url, size_t out_size);
void format_absolute_uri(const struct url_info *url, char *out, size_t out_size);
void format_host_header(const struct url_info *url, char *out, size_t out_size);
int build_redirect_url(const char *location, const struct url_info *base, char *out_url, size_t out_size);

/* --- dns.c --- */
struct addrinfo *resolve_dns(const struct url_info *url, int address_family, int *gai_error);
struct addrinfo *resolve_dns_timeout(const struct url_info *url, int address_family, int *gai_error, int timeout_ms);
struct addrinfo *resolve_host(const struct url_info *url, int address_family,
                               const struct resolve_entry *resolve_entries,
                               int resolve_count, int dns_timeout_ms,
                               struct timespec *dns_start, struct timespec *dns_end,
                               int *gai_error);

/* --- tls.c --- */
void warmup_tls(void);
int init_tls(struct connection *conn, const char *hostname, bool insecure,
             int tls_min_version, int tls_max_version,
             char *error, size_t error_len);

/* --- connect.c --- */
int connect_unix_socket(const char *path, char *error, size_t error_len);
int connect_tcp(const struct addrinfo *addrs, char *connected_ip, size_t connected_ip_size,
                int *connected_family, int connect_timeout_ms,
                struct connect_race_info *race_info, bool happy_eyeballs, int preferred_family,
                const char *bind_interface);
void apply_socket_timeout(int fd, int timeout_ms);
void close_connection(struct connection *conn);
ssize_t connection_read(struct connection *conn, void *buf, size_t len, char *error, size_t error_len);
int connection_write_all(struct connection *conn, const char *buf, size_t len, char *error, size_t error_len);
int connection_writev_all(struct connection *conn, const struct iovec *iov, int iovcnt,
                          char *error, size_t error_len);

/* --- http.c --- */
bool is_redirect_status(int status_code);
void parse_response_headers(char *headers, struct response_info *out);
int send_request(struct connection *conn, const struct url_info *url, const char *method,
                 const char *data, size_t data_len, FILE *upload_file, size_t upload_size,
                 const char **extra_headers, size_t extra_header_count,
                 const char *basic_auth, const char *user_agent,
                 char *error, size_t error_len, bool use_proxy, bool chunked_upload,
                 bool compressed, unsigned int header_flags);
int receive_response(struct connection *conn, const struct timespec *ttfb_start,
                     struct response_info *out, char *error, size_t error_len,
                     FILE *body_out, bool follow_redirects, bool fail_on_http_error, bool head_method);

/* --- compare.c --- */
int run_compare_family(const struct cmdline_opts *c, struct run_options *opts);
int run_compare_urls(const struct cmdline_opts *c, struct run_options *opts);

/* --- cookie.c --- */
void cookie_jar_init(struct cookie_jar *jar);
void cookie_jar_add_set_cookie(struct cookie_jar *jar, const char *set_cookie, const char *request_host);
void cookie_jar_get_header(struct cookie_jar *jar, const char *host, const char *path,
                           bool secure_connection, char *out, size_t out_size);
int cookie_jar_save(const struct cookie_jar *jar, const char *filepath);
void cookie_jar_load(struct cookie_jar *jar, const char *filepath);

/* --- proxy.c --- */
int proxy_connect(struct connection *conn, const char *proxy_host, const char *proxy_port,
                  const struct url_info *target, int connect_timeout_ms,
                  char *error, size_t error_len);

#endif
