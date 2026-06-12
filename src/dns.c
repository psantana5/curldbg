#define _GNU_SOURCE
#include "curldbg.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>

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
    free(finished);
    return result;
}
