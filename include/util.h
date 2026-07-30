#ifndef CURLDBG_UTIL_H
#define CURLDBG_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>
#include <netdb.h>
#include <netinet/in.h>

struct connect_race_info;
struct addrinfo;

__attribute__((noreturn)) void die(const char *msg);
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
bool contains_crlf(const char *s);
void fill_connected_endpoint(const struct addrinfo *ai, char *connected_ip,
                             size_t connected_ip_size, int *connected_family);
void clear_race_info(struct connect_race_info *race_info);
void trim_spaces(char **start);
long deadline_remaining_ms(const struct timespec *start, int max_ms);

#endif
