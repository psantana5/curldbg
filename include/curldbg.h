#ifndef CURLDBG_H
#define CURLDBG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>

#include <netdb.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>

#define MAX_RESOLVE_ENTRIES 16
#define PREVIEW_BYTES 1024
#define HEADER_MAX 16384
#define RESPONSE_READ_BUF 32768
#define DEFAULT_MAX_REDIRECTS 10
#define MAX_COOKIES 256
#define MAX_COOKIE_LEN 4096
#define CURLDBG_VERSION "1.1.0"

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

/* --- util.c --- */
void die(const char *msg);
void set_error(char *error, size_t error_len, const char *fmt, ...);
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

/* --- tls.c --- */
void warmup_tls(void);
int init_tls(struct connection *conn, const char *hostname, bool insecure,
             int tls_min_version, int tls_max_version,
             char *error, size_t error_len);

/* --- connect.c --- */
int connect_tcp(const struct addrinfo *addrs, char *connected_ip, size_t connected_ip_size,
                int *connected_family, int connect_timeout_ms,
                struct connect_race_info *race_info, bool happy_eyeballs, int preferred_family,
                const char *bind_interface);
void apply_socket_timeout(int fd, int timeout_ms);
void close_connection(struct connection *conn);
ssize_t connection_read(struct connection *conn, void *buf, size_t len, char *error, size_t error_len);
int connection_write_all(struct connection *conn, const char *buf, size_t len, char *error, size_t error_len);

/* --- http.c --- */
bool is_redirect_status(int status_code);
void parse_response_headers(char *headers, struct response_info *out);
int send_request(struct connection *conn, const struct url_info *url, const char *method,
                 const char *data, FILE *upload_file, size_t upload_size,
                 const char **extra_headers, size_t extra_header_count,
                 const char *basic_auth, const char *user_agent,
                 char *error, size_t error_len, bool use_proxy, bool chunked_upload);
int receive_response(struct connection *conn, const struct timespec *ttfb_start,
                     struct response_info *out, char *error, size_t error_len,
                     FILE *body_out, bool follow_redirects, bool fail_on_http_error, bool head_method);

/* --- cookie.c --- */
void cookie_jar_init(struct cookie_jar *jar);
void cookie_jar_add_set_cookie(struct cookie_jar *jar, const char *set_cookie, const char *request_host);
void cookie_jar_get_header(struct cookie_jar *jar, const char *host, const char *path,
                           char *out, size_t out_size);
int cookie_jar_save(const struct cookie_jar *jar, const char *filepath);
void cookie_jar_load(struct cookie_jar *jar, const char *filepath);

/* --- proxy.c --- */
int proxy_connect(struct connection *conn, const char *proxy_host, const char *proxy_port,
                  const struct url_info *target, int connect_timeout_ms,
                  char *error, size_t error_len);

#endif
