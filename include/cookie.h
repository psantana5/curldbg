#ifndef CURLDBG_COOKIE_H
#define CURLDBG_COOKIE_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#define MAX_COOKIES 256
#define MAX_COOKIE_LEN 4096

struct cookie_entry {
    char domain[256];
    bool include_subdomains;
    char path[1024];
    char name[256];
    char value[4096];
    bool has_expiry;
    time_t expires_at;
    bool secure;
    bool httponly;
    char samesite[16];
};

struct cookie_jar {
    struct cookie_entry *entries;
    int count;
    int capacity;
};

void cookie_jar_init(struct cookie_jar *jar);
void cookie_jar_destroy(struct cookie_jar *jar);
void cookie_jar_add_set_cookie(struct cookie_jar *jar, const char *set_cookie,
                               const char *request_host, const char *request_path);
void cookie_jar_get_header(struct cookie_jar *jar, const char *host, const char *path,
                           bool secure_connection, char *out, size_t out_size);
int cookie_jar_save(const struct cookie_jar *jar, const char *filepath);
void cookie_jar_load(struct cookie_jar *jar, const char *filepath);

#endif
