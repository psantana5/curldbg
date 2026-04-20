#ifndef CURLDBG_H
#define CURLDBG_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include <netdb.h>
#include <openssl/ssl.h>

#define PREVIEW_BYTES 1024
#define HEADER_MAX 16384
#define DEFAULT_MAX_REDIRECTS 10

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
};

void die(const char *msg);
double ms_between(const struct timespec *start, const struct timespec *end);
bool is_redirect_status(int status_code);
const char *family_name(int family);
int parse_url(const char *url, struct url_info *out);
int format_url(const struct url_info *url, char *out_url, size_t out_size);
int build_redirect_url(
    const char *location,
    const struct url_info *base,
    char *out_url,
    size_t out_size
);
struct addrinfo *resolve_dns(const struct url_info *url, int address_family, int *gai_error);
int connect_tcp(
    const struct addrinfo *addrs,
    char *connected_ip,
    size_t connected_ip_size,
    int *connected_family,
    int connect_timeout_ms,
    struct connect_race_info *race_info
);
void apply_socket_timeout(int fd, int timeout_ms);
void close_connection(struct connection *conn);
int init_tls(struct connection *conn, const char *hostname, char *error, size_t error_len);
int send_request(
    struct connection *conn,
    const struct url_info *url,
    const char *method,
    const char *data,
    char *error,
    size_t error_len
);
int receive_response(
    struct connection *conn,
    const struct timespec *ttfb_start,
    struct response_info *out,
    char *error,
    size_t error_len
);

#endif
