#define _GNU_SOURCE
#include "curldbg.h"

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>

#define DNS_CACHE_SIZE 32

const struct resolve_entry *find_resolve_entry(
    const struct resolve_entry *entries, int count, const char *host, const char *port)
{
    for (int i = 0; i < count; i++) {
        if (strcmp(entries[i].host, host) == 0 && strcmp(entries[i].port, port) == 0)
            return &entries[i];
    }
    return NULL;
}

struct addrinfo *build_addrinfo_from_resolve(const struct resolve_entry *re) {
    size_t total = sizeof(struct addrinfo) + re->ss_len;
    struct addrinfo *ai = calloc(1, total);
    if (ai == NULL) return NULL;
    struct sockaddr *sa = (struct sockaddr *)((char *)ai + sizeof(struct addrinfo));
    memcpy(sa, &re->ss, re->ss_len);
    ai->ai_family = re->family;
    ai->ai_socktype = SOCK_STREAM;
    ai->ai_protocol = IPPROTO_TCP;
    ai->ai_addr = sa;
    ai->ai_addrlen = re->ss_len;
    ai->ai_next = NULL;
    return ai;
}

struct addrinfo *resolve_host(const struct url_info *url,
                               int address_family,
                               const struct resolve_entry *resolve_entries,
                               int resolve_count,
                               struct dns_cache *cache,
                               int dns_timeout_ms,
                               struct timespec *dns_start,
                               struct timespec *dns_end,
                               int *gai_error) {
    const struct resolve_entry *re = find_resolve_entry(resolve_entries, resolve_count,
                                                        url->host, url->port);
    if (re != NULL) {
        struct addrinfo *addrs = build_addrinfo_from_resolve(re);
        *gai_error = (addrs != NULL) ? 0 : EAI_FAIL;
        clock_gettime(CLOCK_MONOTONIC, dns_start);
        *dns_end = *dns_start;
        return addrs;
    }
    if (dns_timeout_ms <= 0) dns_timeout_ms = 5000;
    clock_gettime(CLOCK_MONOTONIC, dns_start);
    struct addrinfo *addrs = resolve_dns_timeout(url, address_family, cache, gai_error, dns_timeout_ms);
    clock_gettime(CLOCK_MONOTONIC, dns_end);
    return addrs;
}

struct dns_cache_entry {
    uint32_t hash;
    char key[256 + 16 + 16];
    struct addrinfo *addrs;
    struct timespec expires;
};

struct dns_cache {
    pthread_mutex_t lock;
    struct dns_cache_entry entries[DNS_CACHE_SIZE];
    int count;
    int ttl_ms;
};

struct dns_cache *dns_cache_create(int ttl_ms) {
    struct dns_cache *cache = calloc(1, sizeof(*cache));
    if (cache == NULL) return NULL;
    pthread_mutex_init(&cache->lock, NULL);
    cache->ttl_ms = (ttl_ms > 0) ? ttl_ms : 300000; /* default 5 minutes */
    return cache;
}

void dns_cache_destroy(struct dns_cache *cache) {
    if (cache == NULL) return;
    pthread_mutex_lock(&cache->lock);
    for (int i = 0; i < cache->count; i++) {
        if (cache->entries[i].addrs != NULL)
            freeaddrinfo(cache->entries[i].addrs);
    }
    pthread_mutex_unlock(&cache->lock);
    pthread_mutex_destroy(&cache->lock);
    free(cache);
}

void dns_cache_key(const char *host, const char *port, int family,
                          char *out, size_t out_size, uint32_t *hash_out) {
    int n = snprintf(out, out_size, "%s:%s:%d", host, port ? port : "", family);
    if (hash_out != NULL && n > 0) {
        uint32_t h = 2166136261u;
        for (int i = 0; i < n && i < (int)out_size - 1; i++)
            h = (h ^ (unsigned char)out[i]) * 16777619u;
        *hash_out = h;
    }
}

struct addrinfo *copy_addrinfo_list(const struct addrinfo *src) {
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

static bool timespec_expired(const struct timespec *expires) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return true;
    if (now.tv_sec > expires->tv_sec) return true;
    if (now.tv_sec == expires->tv_sec && now.tv_nsec >= expires->tv_nsec) return true;
    return false;
}

static void dns_cache_evict_expired(struct dns_cache *cache) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return;
    int i = 0;
    while (i < cache->count) {
        if (timespec_expired(&cache->entries[i].expires)) {
            freeaddrinfo(cache->entries[i].addrs);
            cache->entries[i].addrs = NULL;
            if (i + 1 < cache->count) {
                memmove(&cache->entries[i], &cache->entries[i + 1],
                        (size_t)(cache->count - i - 1) * sizeof(cache->entries[0]));
            }
            cache->count--;
        } else {
            i++;
        }
    }
}

static struct addrinfo *dns_cache_lookup(struct dns_cache *cache,
                                          const char *host, const char *port, int family) {
    if (cache == NULL) return NULL;
    char key[256 + 16 + 16];
    uint32_t hash = 0;
    dns_cache_key(host, port, family, key, sizeof(key), &hash);

    pthread_mutex_lock(&cache->lock);
    dns_cache_evict_expired(cache);
    for (int i = 0; i < cache->count; i++) {
        if (cache->entries[i].hash == hash && strcmp(cache->entries[i].key, key) == 0) {
            struct addrinfo *copy = copy_addrinfo_list(cache->entries[i].addrs);
            /* LRU: move the hit to the MRU end so slot 0 stays the LRU slot */
            if (i + 1 < cache->count) {
                struct dns_cache_entry e = cache->entries[i];
                memmove(&cache->entries[i], &cache->entries[i + 1],
                        (size_t)(cache->count - i - 1) * sizeof(cache->entries[0]));
                cache->entries[cache->count - 1] = e;
            }
            pthread_mutex_unlock(&cache->lock);
            return copy;
        }
    }
    pthread_mutex_unlock(&cache->lock);
    return NULL;
}

static void dns_cache_store(struct dns_cache *cache, const char *host, const char *port, int family,
                            const struct addrinfo *addrs) {
    if (cache == NULL || addrs == NULL) return;

    char key[256 + 16 + 16];
    uint32_t hash = 0;
    dns_cache_key(host, port, family, key, sizeof(key), &hash);

    struct addrinfo *copy = copy_addrinfo_list(addrs);
    if (copy == NULL) return;

    struct timespec expires;
    if (clock_gettime(CLOCK_MONOTONIC, &expires) != 0) {
        freeaddrinfo(copy);
        return;
    }
    expires.tv_sec += cache->ttl_ms / 1000;
    expires.tv_nsec += (cache->ttl_ms % 1000) * 1000000L;
    if (expires.tv_nsec >= 1000000000LL) {
        expires.tv_sec++;
        expires.tv_nsec -= 1000000000LL;
    }

    pthread_mutex_lock(&cache->lock);
    dns_cache_evict_expired(cache);
    for (int i = 0; i < cache->count; i++) {
        if (cache->entries[i].hash == hash && strcmp(cache->entries[i].key, key) == 0) {
            freeaddrinfo(cache->entries[i].addrs);
            cache->entries[i].addrs = copy;
            cache->entries[i].expires = expires;
            pthread_mutex_unlock(&cache->lock);
            return;
        }
    }
    if (cache->count < DNS_CACHE_SIZE) {
        cache->entries[cache->count].hash = hash;
        snprintf(cache->entries[cache->count].key,
                 sizeof(cache->entries[0].key), "%s", key);
        cache->entries[cache->count].addrs = copy;
        cache->entries[cache->count].expires = expires;
        cache->count++;
    } else {
        freeaddrinfo(cache->entries[0].addrs);
        memmove(&cache->entries[0], &cache->entries[1],
                (size_t)(DNS_CACHE_SIZE - 1) * sizeof(cache->entries[0]));
        cache->entries[DNS_CACHE_SIZE - 1].hash = hash;
        snprintf(cache->entries[DNS_CACHE_SIZE - 1].key,
                 sizeof(cache->entries[0].key), "%s", key);
        cache->entries[DNS_CACHE_SIZE - 1].addrs = copy;
        cache->entries[DNS_CACHE_SIZE - 1].expires = expires;
    }
    pthread_mutex_unlock(&cache->lock);
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
    bool self_free;
    pthread_mutex_t mutex;
};

static void *dns_thread_run(void *arg) {
    struct dns_thread_arg *a = arg;
    struct addrinfo *res = resolve_dns(&a->url, a->address_family, &a->gai_error);

    pthread_mutex_lock(&a->mutex);
    a->result = res;
    bool self_free = a->self_free;
    pthread_mutex_unlock(&a->mutex);

    if (self_free) {
        if (res != NULL) freeaddrinfo(res);
        pthread_mutex_destroy(&a->mutex);
        free(a);
        return NULL;
    }
    return arg;
}

struct addrinfo *resolve_dns_timeout(
    const struct url_info *url,
    int address_family,
    struct dns_cache *cache,
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

    struct addrinfo *cached = dns_cache_lookup(cache, url->host, url->port, address_family);
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
    arg->self_free = false;
    pthread_mutex_init(&arg->mutex, NULL);

    pthread_t thread;
    if (pthread_create(&thread, NULL, dns_thread_run, arg) != 0) {
        pthread_mutex_destroy(&arg->mutex);
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
        pthread_mutex_lock(&arg->mutex);
        arg->self_free = true;
        pthread_mutex_unlock(&arg->mutex);
        pthread_detach(thread);
        if (gai_error != NULL) *gai_error = EAI_AGAIN;
        return NULL;
    }

    struct addrinfo *result = NULL;
    if (finished != NULL) {
        result = finished->result;
        if (gai_error != NULL) *gai_error = finished->gai_error;
        pthread_mutex_destroy(&finished->mutex);
        free(finished);
    }
    if (result != NULL && gai_error != NULL && *gai_error == 0) {
        dns_cache_store(cache, url->host, url->port, address_family, result);
    }
    return result;
}
