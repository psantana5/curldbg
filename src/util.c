#define _GNU_SOURCE
#include "curldbg.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>

void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void set_error(char *error, size_t error_len, const char *fmt, ...) {
    va_list args;
    if (error == NULL || error_len == 0) {
        return;
    }
    va_start(args, fmt);
    vsnprintf(error, error_len, fmt, args);
    va_end(args);
}

void set_ssl_error(char *error, size_t error_len, const char *prefix) {
    unsigned long err = ERR_get_error();
    if (err != 0) {
        char openssl_msg[256];
        ERR_error_string_n(err, openssl_msg, sizeof(openssl_msg));
        set_error(error, error_len, "%s: %s", prefix, openssl_msg);
    } else {
        set_error(error, error_len, "%s", prefix);
    }
}

double ms_between(const struct timespec *start, const struct timespec *end) {
    double sec = (double)(end->tv_sec - start->tv_sec) * 1000.0;
    double nsec = (double)(end->tv_nsec - start->tv_nsec) / 1000000.0;
    return sec + nsec;
}

const char *family_name(int family) {
    if (family == AF_INET) return "IPv4";
    if (family == AF_INET6) return "IPv6";
    return "Unknown";
}

int base64_encode(const unsigned char *input, size_t len, char *out, size_t out_len) {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0, o = 0;
    size_t out_needed = 4 * ((len + 2) / 3);
    if (out_len < out_needed + 1) return -1;
    while (i < len) {
        size_t rem = len - i;
        unsigned int octet_a = input[i];
        unsigned int octet_b = (rem > 1) ? input[i + 1] : 0;
        unsigned int octet_c = (rem > 2) ? input[i + 2] : 0;
        i += (rem >= 3) ? 3 : rem;
        unsigned int triple = (octet_a << 16) | (octet_b << 8) | octet_c;
        out[o++] = table[(triple >> 18) & 0x3F];
        out[o++] = table[(triple >> 12) & 0x3F];
        out[o++] = (rem > 1) ? table[(triple >> 6) & 0x3F] : '=';
        out[o++] = (rem > 2) ? table[triple & 0x3F] : '=';
    }
    out[o] = '\0';
    return 0;
}

int append_str(char *buf, size_t buf_size, size_t *offset, const char *str) {
    size_t len = strlen(str);
    if (*offset + len >= buf_size) return -1;
    memcpy(buf + *offset, str, len);
    *offset += len;
    buf[*offset] = '\0';
    return 0;
}

bool is_timeout_errno(int err) {
    return err == EAGAIN || err == EWOULDBLOCK || err == ETIMEDOUT;
}

long long now_ms_monotonic(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (long long)ts.tv_sec * 1000LL + (long long)(ts.tv_nsec / 1000000LL);
}

int set_nonblocking(int fd, bool enabled) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (enabled)
        flags |= O_NONBLOCK;
    else
        flags &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

void fill_connected_endpoint(
    const struct addrinfo *ai,
    char *connected_ip, size_t connected_ip_size,
    int *connected_family
) {
    if (ai == NULL || connected_ip_size == 0) return;
    socklen_t hostlen = (connected_ip_size > (size_t)UINT_MAX) ? (socklen_t)UINT_MAX : (socklen_t)connected_ip_size;
    if (getnameinfo(ai->ai_addr, ai->ai_addrlen, connected_ip, hostlen, NULL, 0, NI_NUMERICHOST) != 0) {
        strncpy(connected_ip, "unknown", connected_ip_size);
        connected_ip[connected_ip_size - 1] = '\0';
    }
    *connected_family = ai->ai_family;
}

void clear_race_info(struct connect_race_info *race_info) {
    if (race_info == NULL) return;
    memset(race_info, 0, sizeof(*race_info));
}

void trim_spaces(char **start) {
    while (**start == ' ' || **start == '\t') (*start)++;
}

bool contains_crlf(const char *s) {
    if (s == NULL) return false;
    for (const char *p = s; *p != '\0'; p++) {
        if (*p == '\r' || *p == '\n') return true;
    }
    return false;
}

long deadline_remaining_ms(const struct timespec *start, int max_ms) {
    if (max_ms <= 0) return -1;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    long long elapsed_ns = (long long)(now.tv_sec - start->tv_sec) * 1000000000LL +
                           (long long)(now.tv_nsec - start->tv_nsec);
    long elapsed_ms = (long)(elapsed_ns / 1000000LL);
    if (elapsed_ms >= max_ms) return 0;
    return max_ms - elapsed_ms;
}

int url_encode(const char *input, char *output, size_t output_size) {
    static const char hex[] = "0123456789ABCDEF";
    size_t o = 0;
    for (const char *p = input; *p != '\0'; p++) {
        unsigned char c = (unsigned char)*p;
        if (isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~') {
            if (o + 1 >= output_size) return -1;
            output[o++] = (char)c;
        } else if (c == ' ') {
            if (o + 3 >= output_size) return -1;
            output[o++] = '%'; output[o++] = '2'; output[o++] = '0';
        } else {
            if (o + 3 >= output_size) return -1;
            output[o++] = '%';
            output[o++] = hex[c >> 4];
            output[o++] = hex[c & 0xf];
        }
    }
    output[o] = '\0';
    return 0;
}
