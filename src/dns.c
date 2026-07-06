#define _GNU_SOURCE
#include "curldbg.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>

#define DNS_CACHE_SIZE 32

struct dns_cache_entry {
    char key[256 + 16 + 16];
    struct addrinfo *addrs;
};

static pthread_mutex_t g_dns_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static struct dns_cache_entry g_dns_cache[DNS_CACHE_SIZE];
static int g_dns_cache_count = 0;

static void dns_cache_key(const char *host, const char *port, int family,
                          char *out, size_t out_size) {
    snprintf(out, out_size, "%s:%s:%d", host, port ? port : "", family);
}

static struct addrinfo *copy_addrinfo_list(const struct addrinfo *src) {
    struct addrinfo *head = NULL;
    struct addrinfo **tail = &head;

    for (const struct addrinfo *ai = src; ai != NULL; ai = ai->ai_next) {
        size_t total = sizeof(struct addrinfo) + ai->ai_addrlen;
        struct addrinfo *copy = calloc(1, total);
        if (copy == NULL) {
            freeaddrinfo(head);
            return NULL;
        }
        copy->ai_flags = ai->ai_flags;
        copy->ai_family = ai->ai_family;
        copy->ai_socktype = ai->ai_socktype;
        copy->ai_protocol = ai->ai_protocol;
        copy->ai_addrlen = ai->ai_addrlen;
        if (ai->ai_addrlen > 0) {
            struct sockaddr *sa = (struct sockaddr *)((char *)copy + sizeof(struct addrinfo));
            memcpy(sa, ai->ai_addr, ai->ai_addrlen);
            copy->ai_addr = sa;
        }
        *tail = copy;
        tail = &copy->ai_next;
    }
    return head;
}

static struct addrinfo *dns_cache_lookup(const char *host, const char *port, int family) {
    char key[256 + 16 + 16];
    dns_cache_key(host, port, family, key, sizeof(key));

    pthread_mutex_lock(&g_dns_cache_lock);
    for (int i = 0; i < g_dns_cache_count; i++) {
        if (strcmp(g_dns_cache[i].key, key) == 0) {
            struct addrinfo *copy = copy_addrinfo_list(g_dns_cache[i].addrs);
            pthread_mutex_unlock(&g_dns_cache_lock);
            return copy;
        }
    }
    pthread_mutex_unlock(&g_dns_cache_lock);
    return NULL;
}

static void dns_cache_store(const char *host, const char *port, int family,
                            struct addrinfo *addrs) {
    if (addrs == NULL) return;

    char key[256 + 16 + 16];
    dns_cache_key(host, port, family, key, sizeof(key));

    struct addrinfo *copy = copy_addrinfo_list(addrs);
    if (copy == NULL) return;

    pthread_mutex_lock(&g_dns_cache_lock);
    for (int i = 0; i < g_dns_cache_count; i++) {
        if (strcmp(g_dns_cache[i].key, key) == 0) {
            freeaddrinfo(g_dns_cache[i].addrs);
            g_dns_cache[i].addrs = copy;
            pthread_mutex_unlock(&g_dns_cache_lock);
            return;
        }
    }
    if (g_dns_cache_count < DNS_CACHE_SIZE) {
        snprintf(g_dns_cache[g_dns_cache_count].key,
                 sizeof(g_dns_cache[0].key), "%s", key);
        g_dns_cache[g_dns_cache_count].addrs = copy;
        g_dns_cache_count++;
    } else {
        /* Evict oldest entry (FIFO). */
        freeaddrinfo(g_dns_cache[0].addrs);
        memmove(&g_dns_cache[0], &g_dns_cache[1],
                (size_t)(DNS_CACHE_SIZE - 1) * sizeof(g_dns_cache[0]));
        snprintf(g_dns_cache[DNS_CACHE_SIZE - 1].key,
                 sizeof(g_dns_cache[0].key), "%s", key);
        g_dns_cache[DNS_CACHE_SIZE - 1].addrs = copy;
    }
    pthread_mutex_unlock(&g_dns_cache_lock);
}

/* Resolve all candidate IPs (IPv4/IPv6) for host:port. */
struct addrinfo *resolve_dns(const struct url_info *url, int address_family, int *gai_error) {
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = address_family;
    hints.ai_socktype = SOCK_STREAM;

    rc = getaddrinfo(url->host, url->port, &hints, &result);
    if (rc != 0) {
        if (gai_error != NULL) *gai_error = rc;
        return NULL;
    }
    if (gai_error != NULL) *gai_error = 0;
    return result;
}

struct dns_thread_arg {
    struct url_info url;
    int address_family;
    struct addrinfo *result;
    int gai_error;
};

static void *dns_thread_run(void *arg) {
    struct dns_thread_arg *a = arg;
    a->result = resolve_dns(&a->url, a->address_family, &a->gai_error);
    return arg;
}

struct addrinfo *resolve_dns_timeout(
    const struct url_info *url,
    int address_family,
    int *gai_error,
    int timeout_ms
) {
    if (timeout_ms <= 0) return resolve_dns(url, address_family, gai_error);

    {
        struct in_addr a4;
        struct in6_addr a6;
        if (inet_pton(AF_INET, url->host, &a4) == 1 ||
            inet_pton(AF_INET6, url->host, &a6) == 1)
            return resolve_dns(url, address_family, gai_error);
    }

    struct addrinfo *cached = dns_cache_lookup(url->host, url->port, address_family);
    if (cached != NULL) {
        if (gai_error != NULL) *gai_error = 0;
        return cached;
    }

    struct dns_thread_arg *arg = malloc(sizeof(*arg));
    if (arg == NULL) return resolve_dns(url, address_family, gai_error);

    arg->url = *url;
    arg->address_family = address_family;
    arg->result = NULL;
    arg->gai_error = 0;

    pthread_t thread;
    if (pthread_create(&thread, NULL, dns_thread_run, arg) != 0) {
        free(arg);
        return resolve_dns(url, address_family, gai_error);
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (timeout_ms % 1000) * 1000000LL;
    if (ts.tv_nsec >= 1000000000LL) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000LL;
    }

    struct dns_thread_arg *finished;
    int rc = pthread_timedjoin_np(thread, (void **)&finished, &ts);
    if (rc == ETIMEDOUT) {
        pthread_detach(thread);
        if (gai_error != NULL) *gai_error = EAI_AGAIN;
        return NULL;
    }

    struct addrinfo *result = finished->result;
    if (gai_error != NULL) *gai_error = finished->gai_error;
    if (result != NULL && finished->gai_error == 0) {
        dns_cache_store(url->host, url->port, address_family, result);
    }
    free(finished);
    return result;
}
