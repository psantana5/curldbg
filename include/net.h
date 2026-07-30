#ifndef CURLDBG_NET_H
#define CURLDBG_NET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <openssl/ssl.h>

struct url_info;
struct response_info;

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

struct connect_race_info {
    double winner_connect_ms;
    bool has_loser;
    char loser_ip[NI_MAXHOST];
    int loser_family;
    double loser_connect_ms;
};

struct h2_connection;

struct huff_node {
    uint32_t child[2];
};

#define HUFF_NODE_TERMINAL 0x80000000u

struct connection {
    int fd;
    bool use_tls;
    bool verbose;
    SSL_CTX *ctx;
    SSL *ssl;
    int last_errno;
    bool ctx_owned;
    bool http2;
    struct h2_connection *h2;
};

struct connection_state {
    struct connection conn;
    struct addrinfo *addrs;
    char host[256];
    char port[16];
    bool use_tls;
};

/* DNS */
struct dns_cache;
struct dns_cache *dns_cache_create(int ttl_ms);
void dns_cache_destroy(struct dns_cache *cache);
struct addrinfo *resolve_dns(const struct url_info *url, int address_family, int *gai_error);
struct addrinfo *resolve_dns_timeout(const struct url_info *url, int address_family,
                                      struct dns_cache *cache,
                                      int *gai_error, int timeout_ms);
struct addrinfo *resolve_host(const struct url_info *url, int address_family,
                               const struct resolve_entry *resolve_entries,
                               int resolve_count, struct dns_cache *cache,
                               int dns_timeout_ms,
                               struct timespec *dns_start, struct timespec *dns_end,
                               int *gai_error);

/* TLS */
SSL_CTX *tls_context_create(const struct tls_params *params,
                            char *error, size_t error_len);
void tls_context_free(SSL_CTX *ctx);
int init_tls(struct connection *conn, const char *hostname, bool insecure,
             int tls_min_version, int tls_max_version,
             const struct tls_params *params, SSL_CTX *shared_ctx,
             char *error, size_t error_len);

/* Connect */
int connect_unix_socket(const char *path, char *error, size_t error_len);
int connect_tcp(const struct addrinfo *addrs, char *connected_ip, size_t connected_ip_size,
                int *connected_family, int connect_timeout_ms,
                struct connect_race_info *race_info, bool happy_eyeballs, int preferred_family,
                const char *bind_interface);
int apply_socket_timeout(int fd, int timeout_ms);
void close_connection(struct connection *conn);
ssize_t connection_read(struct connection *conn, void *buf, size_t len,
                        char *error, size_t error_len);
int connection_write_all(struct connection *conn, const char *buf, size_t len,
                         char *error, size_t error_len);
int connection_writev_all(struct connection *conn, const struct iovec *iov, int iovcnt,
                          char *error, size_t error_len);

/* Proxy */
int proxy_connect(struct connection *conn, const struct url_info *target,
                  int connect_timeout_ms, char *error, size_t error_len);

/* HTTP/2 */
bool http2_negotiated(const struct connection *conn);
int http2_init_connection(struct connection *conn, char *error, size_t error_len);
uint32_t http2_send_request(struct connection *conn, const struct url_info *url,
                            const char *method, const char *data, size_t data_len,
                            const char **extra_headers, size_t extra_header_count,
                            const char *user_agent, const char *basic_auth,
                            char *error, size_t error_len);
int http2_receive_response(struct connection *conn, uint32_t stream_id,
                           struct response_info *out,
                           const struct timespec *ttfb_start,
                           FILE *body_out, char *error, size_t error_len);
void http2_cleanup(struct connection *conn);

/* Huffman HPACK */
struct h2_static_entry {
    const char *name;
    size_t name_len;
    const char *value;
    size_t value_len;
};

int huff_tree_init(struct huff_node **tree, int *alloc);
size_t huffman_encode(const unsigned char *input, size_t input_len,
                       unsigned char *output, size_t output_size);
int hpack_decode_string_ext(const struct huff_node *tree,
                             const unsigned char *buf, size_t buf_len,
                             size_t *offset, char *out, size_t out_size,
                             size_t *out_len);
size_t huffman_decode(const struct huff_node *tree,
                       const unsigned char *input, size_t input_len,
                       unsigned char *output, size_t output_size);
int lookup_static_name(const char *name, size_t name_len, int *idx_out);
const struct h2_static_entry *get_static_entry(int idx);
size_t hpack_encode_int(unsigned char *out, size_t out_size,
                         uint64_t value, uint8_t prefix_bits);
int hpack_decode_int(const unsigned char *buf, size_t buf_len,
                      size_t *offset, uint8_t prefix_bits,
                      uint64_t *out);
size_t hpack_encode_string(unsigned char *out, size_t out_size,
                            const char *str, size_t str_len);
int hpack_decode_string(const struct huff_node *tree,
                         const unsigned char *buf, size_t buf_len,
                         size_t *offset, char *out, size_t out_size,
                         size_t *out_len);
int hpack_encode_literal_with_indexing(unsigned char *out, size_t out_size,
                                        uint64_t name_index,
                                        const char *name, size_t name_len,
                                        const char *value, size_t value_len);

#endif
