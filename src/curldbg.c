#include "curldbg.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/err.h>

#define HAPPY_EYEBALLS_DELAY_MS 250

void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

static void set_error(char *error, size_t error_len, const char *fmt, ...) {
    va_list args;
    if (error == NULL || error_len == 0) {
        return;
    }

    va_start(args, fmt);
    vsnprintf(error, error_len, fmt, args);
    va_end(args);
}

static void set_ssl_error(char *error, size_t error_len, const char *prefix) {
    unsigned long err = ERR_get_error();
    if (err != 0) {
        char openssl_msg[256];
        ERR_error_string_n(err, openssl_msg, sizeof(openssl_msg));
        set_error(error, error_len, "%s: %s", prefix, openssl_msg);
    } else {
        set_error(error, error_len, "%s", prefix);
    }
}

static bool is_timeout_errno(int err) {
    return err == EAGAIN || err == EWOULDBLOCK || err == ETIMEDOUT;
}

static long long now_ms_monotonic(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (long long)ts.tv_sec * 1000LL + (long long)(ts.tv_nsec / 1000000LL);
}

static int set_nonblocking(int fd, bool enabled) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }

    if (enabled) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }

    return fcntl(fd, F_SETFL, flags);
}

static void fill_connected_endpoint(
    const struct addrinfo *ai,
    char *connected_ip,
    size_t connected_ip_size,
    int *connected_family
) {
    if (getnameinfo(
            ai->ai_addr,
            ai->ai_addrlen,
            connected_ip,
            connected_ip_size,
            NULL,
            0,
            NI_NUMERICHOST
        ) != 0) {
        strncpy(connected_ip, "unknown", connected_ip_size);
        connected_ip[connected_ip_size - 1] = '\0';
    }
    *connected_family = ai->ai_family;
}

static void clear_race_info(struct connect_race_info *race_info) {
    if (race_info == NULL) {
        return;
    }
    memset(race_info, 0, sizeof(*race_info));
}

double ms_between(const struct timespec *start, const struct timespec *end) {
    double sec = (double)(end->tv_sec - start->tv_sec) * 1000.0;
    double nsec = (double)(end->tv_nsec - start->tv_nsec) / 1000000.0;
    return sec + nsec;
}

bool is_redirect_status(int status_code) {
    return status_code == 301 || status_code == 302 || status_code == 303 ||
           status_code == 307 || status_code == 308;
}

const char *family_name(int family) {
    if (family == AF_INET) {
        return "IPv4";
    }
    if (family == AF_INET6) {
        return "IPv6";
    }
    return "Unknown";
}

static void trim_spaces(char **start) {
    while (**start == ' ' || **start == '\t') {
        (*start)++;
    }
}

/* Parse [http(s)://]host[:port][/path] into host/port/path. */
int parse_url(const char *url, struct url_info *out) {
    const char *authority_start;
    const char *path_start;
    char authority[512];
    size_t authority_len;
    const char *http_prefix = "http://";
    const char *https_prefix = "https://";

    if (strncmp(url, http_prefix, strlen(http_prefix)) == 0) {
        authority_start = url + strlen(http_prefix);
        out->use_tls = false;
        strcpy(out->port, "80");
    } else if (strncmp(url, https_prefix, strlen(https_prefix)) == 0) {
        authority_start = url + strlen(https_prefix);
        out->use_tls = true;
        strcpy(out->port, "443");
    } else {
        if (strstr(url, "://") != NULL) {
            fprintf(stderr, "Only http:// and https:// URLs are supported\n");
            return -1;
        }
        authority_start = url;
        out->use_tls = true;
        strcpy(out->port, "443");
    }

    out->has_explicit_port = false;
    path_start = strchr(authority_start, '/');
    authority_len = path_start ? (size_t)(path_start - authority_start) : strlen(authority_start);

    if (authority_len == 0 || authority_len >= sizeof(authority)) {
        fprintf(stderr, "Invalid URL authority\n");
        return -1;
    }

    memcpy(authority, authority_start, authority_len);
    authority[authority_len] = '\0';

    if (authority[0] == '[') {
        char *closing = strchr(authority, ']');
        if (closing == NULL) {
            fprintf(stderr, "Invalid IPv6 host format\n");
            return -1;
        }

        *closing = '\0';
        if (strlen(authority + 1) >= sizeof(out->host)) {
            fprintf(stderr, "Host is too long\n");
            return -1;
        }
        strcpy(out->host, authority + 1);

        if (*(closing + 1) == ':') {
            if (strlen(closing + 2) == 0 || strlen(closing + 2) >= sizeof(out->port)) {
                fprintf(stderr, "Invalid port\n");
                return -1;
            }
            strcpy(out->port, closing + 2);
            out->has_explicit_port = true;
        } else if (*(closing + 1) != '\0') {
            fprintf(stderr, "Invalid authority format\n");
            return -1;
        }
    } else {
        char *colon = strrchr(authority, ':');
        if (colon != NULL) {
            *colon = '\0';
            if (strlen(colon + 1) == 0 || strlen(colon + 1) >= sizeof(out->port)) {
                fprintf(stderr, "Invalid port\n");
                return -1;
            }
            strcpy(out->port, colon + 1);
            out->has_explicit_port = true;
        }

        if (strlen(authority) == 0 || strlen(authority) >= sizeof(out->host)) {
            fprintf(stderr, "Invalid host\n");
            return -1;
        }
        strcpy(out->host, authority);
    }

    if (path_start == NULL) {
        strcpy(out->path, "/");
    } else {
        if (strlen(path_start) >= sizeof(out->path)) {
            fprintf(stderr, "Path is too long\n");
            return -1;
        }
        strcpy(out->path, path_start);
    }

    return 0;
}

static void parse_response_headers(char *headers, struct response_info *out) {
    char *line;
    char *line_end;

    out->status_code = 0;
    out->location[0] = '\0';

    line_end = strstr(headers, "\r\n");
    if (line_end == NULL) {
        return;
    }
    *line_end = '\0';
    if (sscanf(headers, "HTTP/%*d.%*d %d", &out->status_code) != 1) {
        out->status_code = 0;
    }

    line = line_end + 2;
    while (*line != '\0') {
        char *next = strstr(line, "\r\n");
        if (next == NULL) {
            break;
        }
        *next = '\0';

        if (strncasecmp(line, "Location:", 9) == 0) {
            char *value = line + 9;
            trim_spaces(&value);
            strncpy(out->location, value, sizeof(out->location) - 1);
            out->location[sizeof(out->location) - 1] = '\0';
            break;
        }

        line = next + 2;
    }
}

int build_redirect_url(
    const char *location,
    const struct url_info *base,
    char *out_url,
    size_t out_size
) {
    const char *scheme = base->use_tls ? "https" : "http";
    bool is_ipv6_literal = strchr(base->host, ':') != NULL;
    const char *path_to_use = base->path;
    char base_dir[1024];
    int n;

    if (strncmp(location, "http://", 7) == 0 || strncmp(location, "https://", 8) == 0) {
        if (strlen(location) >= out_size) {
            return -1;
        }
        strcpy(out_url, location);
        return 0;
    }

    if (location[0] != '/') {
        const char *slash = strrchr(base->path, '/');
        if (slash == NULL) {
            strcpy(base_dir, "/");
        } else {
            size_t keep = (size_t)(slash - base->path) + 1;
            if (keep >= sizeof(base_dir)) {
                return -1;
            }
            memcpy(base_dir, base->path, keep);
            base_dir[keep] = '\0';
        }

        if (snprintf(base_dir + strlen(base_dir), sizeof(base_dir) - strlen(base_dir), "%s", location) >=
            (int)(sizeof(base_dir) - strlen(base_dir))) {
            return -1;
        }
        path_to_use = base_dir;
    } else {
        path_to_use = location;
    }

    if (base->has_explicit_port) {
        if (is_ipv6_literal) {
            n = snprintf(out_url, out_size, "%s://[%s]:%s%s", scheme, base->host, base->port, path_to_use);
        } else {
            n = snprintf(out_url, out_size, "%s://%s:%s%s", scheme, base->host, base->port, path_to_use);
        }
    } else {
        if (is_ipv6_literal) {
            n = snprintf(out_url, out_size, "%s://[%s]%s", scheme, base->host, path_to_use);
        } else {
            n = snprintf(out_url, out_size, "%s://%s%s", scheme, base->host, path_to_use);
        }
    }

    if (n < 0 || (size_t)n >= out_size) {
        return -1;
    }
    return 0;
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
        if (gai_error != NULL) {
            *gai_error = rc;
        }
        return NULL;
    }

    if (gai_error != NULL) {
        *gai_error = 0;
    }

    return result;
}

static int connect_with_timeout(int fd, const struct sockaddr *addr, socklen_t addrlen, int timeout_ms) {
    int flags;
    int rc;

    if (timeout_ms <= 0) {
        return connect(fd, addr, addrlen);
    }

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        return -1;
    }

    rc = connect(fd, addr, addrlen);
    if (rc == 0) {
        if (fcntl(fd, F_SETFL, flags) != 0) {
            return -1;
        }
        return 0;
    }
    if (errno != EINPROGRESS) {
        (void)fcntl(fd, F_SETFL, flags);
        return -1;
    }

    for (;;) {
        struct pollfd pfd;
        int poll_rc;
        int so_error = 0;
        socklen_t so_error_len = sizeof(so_error);

        pfd.fd = fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        poll_rc = poll(&pfd, 1, timeout_ms);
        if (poll_rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            (void)fcntl(fd, F_SETFL, flags);
            return -1;
        }
        if (poll_rc == 0) {
            errno = ETIMEDOUT;
            (void)fcntl(fd, F_SETFL, flags);
            return -1;
        }

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len) != 0) {
            (void)fcntl(fd, F_SETFL, flags);
            return -1;
        }
        if (so_error != 0) {
            errno = so_error;
            (void)fcntl(fd, F_SETFL, flags);
            return -1;
        }
        break;
    }

    if (fcntl(fd, F_SETFL, flags) != 0) {
        return -1;
    }
    return 0;
}

static int connect_tcp_sequential(
    const struct addrinfo *addrs,
    char *connected_ip,
    size_t connected_ip_size,
    int *connected_family,
    int connect_timeout_ms,
    struct connect_race_info *race_info
) {
    const struct addrinfo *ai;
    int last_errno = 0;

    clear_race_info(race_info);

    for (ai = addrs; ai != NULL; ai = ai->ai_next) {
        struct timespec start_ts;
        struct timespec end_ts;
        int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            last_errno = errno;
            continue;
        }

        if (clock_gettime(CLOCK_MONOTONIC, &start_ts) != 0) {
            close(fd);
            last_errno = errno;
            continue;
        }
        if (connect_with_timeout(fd, ai->ai_addr, ai->ai_addrlen, connect_timeout_ms) == 0) {
            if (clock_gettime(CLOCK_MONOTONIC, &end_ts) == 0 && race_info != NULL) {
                race_info->winner_connect_ms = ms_between(&start_ts, &end_ts);
            }
            fill_connected_endpoint(ai, connected_ip, connected_ip_size, connected_family);
            return fd;
        }

        (void)clock_gettime(CLOCK_MONOTONIC, &end_ts);
        last_errno = errno;
        close(fd);
    }

    if (last_errno != 0) {
        errno = last_errno;
    } else {
        errno = ECONNREFUSED;
    }
    return -1;
}

struct he_attempt {
    const struct addrinfo *ai;
    int fd;
    bool active;
    long long started_ms;
    bool finished;
    bool success;
    double connect_ms;
};

static int connect_tcp_happy_eyeballs(
    const struct addrinfo *addrs,
    char *connected_ip,
    size_t connected_ip_size,
    int *connected_family,
    int connect_timeout_ms,
    struct connect_race_info *race_info
) {
    const struct addrinfo *ai;
    size_t total = 0;
    size_t v4_total = 0;
    size_t v6_total = 0;
    const struct addrinfo **v4 = NULL;
    const struct addrinfo **v6 = NULL;
    struct he_attempt *attempts = NULL;
    struct pollfd *pfds = NULL;
    size_t next_index = 0;
    int active_count = 0;
    int last_errno = 0;
    long long next_start_ms;
    int winner_fd = -1;
    size_t winner_idx = 0;
    bool have_winner = false;
    long long race_start_ms;

    for (ai = addrs; ai != NULL; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) {
            v4_total++;
            total++;
        } else if (ai->ai_family == AF_INET6) {
            v6_total++;
            total++;
        }
    }

    if (v4_total == 0 || v6_total == 0 || total == 0) {
        return connect_tcp_sequential(
            addrs,
            connected_ip,
            connected_ip_size,
            connected_family,
            connect_timeout_ms,
            race_info
        );
    }

    clear_race_info(race_info);

    v4 = calloc(v4_total, sizeof(*v4));
    v6 = calloc(v6_total, sizeof(*v6));
    attempts = calloc(total, sizeof(*attempts));
    pfds = calloc(total, sizeof(*pfds));
    if (v4 == NULL || v6 == NULL || attempts == NULL || pfds == NULL) {
        free(v4);
        free(v6);
        free(attempts);
        free(pfds);
        errno = ENOMEM;
        return -1;
    }

    {
        size_t i4 = 0;
        size_t i6 = 0;
        size_t idx = 0;

        for (ai = addrs; ai != NULL; ai = ai->ai_next) {
            if (ai->ai_family == AF_INET) {
                v4[i4++] = ai;
            } else if (ai->ai_family == AF_INET6) {
                v6[i6++] = ai;
            }
        }

        i4 = 0;
        i6 = 0;
        while (i4 < v4_total || i6 < v6_total) {
            if (i6 < v6_total) {
                attempts[idx].ai = v6[i6++];
                attempts[idx].fd = -1;
                idx++;
            }
            if (i4 < v4_total) {
                attempts[idx].ai = v4[i4++];
                attempts[idx].fd = -1;
                idx++;
            }
        }
    }

    race_start_ms = now_ms_monotonic();
    next_start_ms = race_start_ms;

    for (;;) {
        long long now = now_ms_monotonic();

        if (next_index < total && now >= next_start_ms) {
            int fd = socket(attempts[next_index].ai->ai_family, SOCK_STREAM, attempts[next_index].ai->ai_protocol);
            if (fd >= 0) {
                if (set_nonblocking(fd, true) != 0) {
                    last_errno = errno;
                    close(fd);
                } else {
                    int rc = connect(
                        fd,
                        attempts[next_index].ai->ai_addr,
                        attempts[next_index].ai->ai_addrlen
                    );
                    if (rc == 0) {
                        attempts[next_index].fd = fd;
                        attempts[next_index].finished = true;
                        attempts[next_index].success = true;
                        attempts[next_index].connect_ms = (double)(now - race_start_ms);
                        have_winner = true;
                        winner_fd = fd;
                        winner_idx = next_index;
                        break;
                    }
                    if (errno == EINPROGRESS) {
                        attempts[next_index].fd = fd;
                        attempts[next_index].active = true;
                        attempts[next_index].started_ms = now;
                        active_count++;
                    } else {
                        last_errno = errno;
                        attempts[next_index].finished = true;
                        attempts[next_index].success = false;
                        attempts[next_index].connect_ms = (double)(now - race_start_ms);
                        close(fd);
                    }
                }
            } else {
                last_errno = errno;
            }

            next_index++;
            next_start_ms = now + HAPPY_EYEBALLS_DELAY_MS;
            continue;
        }

        if (active_count == 0) {
            if (next_index >= total) {
                break;
            }

            now = now_ms_monotonic();
            if (next_start_ms > now) {
                int sleep_ms = (int)(next_start_ms - now);
                (void)poll(NULL, 0, sleep_ms);
            }
            continue;
        }

        {
            nfds_t nfds = 0;
            int poll_timeout = -1;

            now = now_ms_monotonic();

            if (next_index < total && next_start_ms > now) {
                poll_timeout = (int)(next_start_ms - now);
            } else if (next_index < total) {
                poll_timeout = 0;
            }

            if (connect_timeout_ms > 0) {
                int nearest_deadline = -1;
                for (size_t i = 0; i < total; i++) {
                    if (!attempts[i].active) {
                        continue;
                    }
                    long long remain = (attempts[i].started_ms + connect_timeout_ms) - now;
                    int remain_ms = (remain <= 0) ? 0 : (int)remain;
                    if (nearest_deadline < 0 || remain_ms < nearest_deadline) {
                        nearest_deadline = remain_ms;
                    }
                }
                if (nearest_deadline >= 0 && (poll_timeout < 0 || nearest_deadline < poll_timeout)) {
                    poll_timeout = nearest_deadline;
                }
            }

            for (size_t i = 0; i < total; i++) {
                if (!attempts[i].active) {
                    continue;
                }
                pfds[nfds].fd = attempts[i].fd;
                pfds[nfds].events = POLLOUT;
                pfds[nfds].revents = 0;
                nfds++;
            }

            if (poll(pfds, nfds, poll_timeout) < 0) {
                if (errno == EINTR) {
                    continue;
                }
                last_errno = errno;
                break;
            }

            now = now_ms_monotonic();

            for (nfds_t pidx = 0; pidx < nfds; pidx++) {
                if ((pfds[pidx].revents & (POLLOUT | POLLERR | POLLHUP)) == 0) {
                    continue;
                }
                for (size_t i = 0; i < total; i++) {
                    if (!attempts[i].active || attempts[i].fd != pfds[pidx].fd) {
                        continue;
                    }

                    {
                        int so_error = 0;
                        socklen_t so_len = sizeof(so_error);
                        if (getsockopt(attempts[i].fd, SOL_SOCKET, SO_ERROR, &so_error, &so_len) != 0) {
                            so_error = errno;
                        }

                        if (so_error == 0) {
                            attempts[i].finished = true;
                            attempts[i].success = true;
                            attempts[i].connect_ms = (double)(now - race_start_ms);
                            have_winner = true;
                            winner_fd = attempts[i].fd;
                            winner_idx = i;
                            attempts[i].active = false;
                            active_count--;
                        } else {
                            last_errno = so_error;
                            attempts[i].finished = true;
                            attempts[i].success = false;
                            attempts[i].connect_ms = (double)(now - race_start_ms);
                            close(attempts[i].fd);
                            attempts[i].fd = -1;
                            attempts[i].active = false;
                            active_count--;
                        }
                    }

                    break;
                }

            }

            if (!have_winner && connect_timeout_ms > 0) {
                for (size_t i = 0; i < total; i++) {
                    if (!attempts[i].active) {
                        continue;
                    }
                    if (now - attempts[i].started_ms >= connect_timeout_ms) {
                        last_errno = ETIMEDOUT;
                        attempts[i].finished = true;
                        attempts[i].success = false;
                        attempts[i].connect_ms = (double)(now - race_start_ms);
                        close(attempts[i].fd);
                        attempts[i].fd = -1;
                        attempts[i].active = false;
                        active_count--;
                    }
                }
            }
        }

        if (have_winner) {
            break;
        }
    }

    if (have_winner) {
        long long now = now_ms_monotonic();
        size_t loser_idx = total;

        if (now < race_start_ms) {
            now = race_start_ms;
        }

        for (size_t i = 0; i < total; i++) {
            struct pollfd pfd;
            int so_error = 0;
            socklen_t so_len = sizeof(so_error);
            int rc;

            if (i == winner_idx || !attempts[i].active || attempts[i].fd < 0) {
                continue;
            }

            memset(&pfd, 0, sizeof(pfd));
            pfd.fd = attempts[i].fd;
            pfd.events = POLLOUT;
            rc = poll(&pfd, 1, 0);
            if (rc <= 0 || !(pfd.revents & (POLLOUT | POLLERR | POLLHUP | POLLNVAL))) {
                continue;
            }

            if (getsockopt(attempts[i].fd, SOL_SOCKET, SO_ERROR, &so_error, &so_len) != 0) {
                so_error = errno;
            }
            attempts[i].finished = true;
            attempts[i].connect_ms = (double)(now - race_start_ms);
            attempts[i].active = false;
            if (so_error == 0) {
                attempts[i].success = true;
            } else {
                attempts[i].success = false;
            }
        }

        if (race_info != NULL) {
            race_info->winner_connect_ms = attempts[winner_idx].connect_ms;
        }

        for (size_t i = 0; i < total; i++) {
            if (i == winner_idx || !attempts[i].finished || !attempts[i].success) {
                continue;
            }

            if (loser_idx == total || attempts[i].connect_ms > attempts[loser_idx].connect_ms) {
                loser_idx = i;
            }
        }

        if (race_info != NULL && loser_idx != total) {
            race_info->has_loser = true;
            race_info->loser_connect_ms = attempts[loser_idx].connect_ms;
            fill_connected_endpoint(
                attempts[loser_idx].ai,
                race_info->loser_ip,
                sizeof(race_info->loser_ip),
                &race_info->loser_family
            );
        }

        for (size_t i = 0; i < total; i++) {
            if (i == winner_idx) {
                continue;
            }
            if (attempts[i].fd >= 0) {
                close(attempts[i].fd);
                attempts[i].fd = -1;
            }
        }

        if (set_nonblocking(winner_fd, false) != 0) {
            last_errno = errno;
            close(winner_fd);
            winner_fd = -1;
        } else {
            fill_connected_endpoint(attempts[winner_idx].ai, connected_ip, connected_ip_size, connected_family);
        }
    }

    free(v4);
    free(v6);
    free(pfds);
    free(attempts);

    if (winner_fd >= 0) {
        return winner_fd;
    }

    if (last_errno != 0) {
        errno = last_errno;
    } else {
        errno = ECONNREFUSED;
    }
    return -1;
}

/* Try each resolved address until one connect() succeeds. */
int connect_tcp(
    const struct addrinfo *addrs,
    char *connected_ip,
    size_t connected_ip_size,
    int *connected_family,
    int connect_timeout_ms,
    struct connect_race_info *race_info
) {
    return connect_tcp_happy_eyeballs(
        addrs,
        connected_ip,
        connected_ip_size,
        connected_family,
        connect_timeout_ms,
        race_info
    );
}

void apply_socket_timeout(int fd, int timeout_ms) {
    struct timeval tv;

    if (timeout_ms <= 0) {
        return;
    }

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
        die("setsockopt SO_RCVTIMEO");
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) {
        die("setsockopt SO_SNDTIMEO");
    }
}

void close_connection(struct connection *conn) {
    if (conn->ssl != NULL) {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
    if (conn->ctx != NULL) {
        SSL_CTX_free(conn->ctx);
        conn->ctx = NULL;
    }
    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }
}

int init_tls(struct connection *conn, const char *hostname, char *error, size_t error_len) {
    if (OPENSSL_init_ssl(0, NULL) != 1) {
        set_ssl_error(error, error_len, "OPENSSL_init_ssl failed");
        return -1;
    }

    conn->ctx = SSL_CTX_new(TLS_client_method());
    if (conn->ctx == NULL) {
        set_ssl_error(error, error_len, "SSL_CTX_new failed");
        return -1;
    }

#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
    SSL_CTX_set_options(conn->ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif

    SSL_CTX_set_verify(conn->ctx, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_set_default_verify_paths(conn->ctx) != 1) {
        set_ssl_error(error, error_len, "Could not load system CA certificates");
        return -1;
    }

    conn->ssl = SSL_new(conn->ctx);
    if (conn->ssl == NULL) {
        set_ssl_error(error, error_len, "SSL_new failed");
        return -1;
    }

    if (SSL_set_tlsext_host_name(conn->ssl, hostname) != 1) {
        set_ssl_error(error, error_len, "Failed to set TLS SNI hostname");
        return -1;
    }

    if (SSL_set1_host(conn->ssl, hostname) != 1) {
        set_ssl_error(error, error_len, "Failed to configure TLS hostname verification");
        return -1;
    }

    if (SSL_set_fd(conn->ssl, conn->fd) != 1) {
        set_ssl_error(error, error_len, "SSL_set_fd failed");
        return -1;
    }

    {
        int connect_rc = SSL_connect(conn->ssl);
        if (connect_rc != 1) {
            int ssl_err = SSL_get_error(conn->ssl, connect_rc);
            if ((ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) ||
                (ssl_err == SSL_ERROR_SYSCALL && is_timeout_errno(errno))) {
                set_error(error, error_len, "TLS handshake timeout");
                return -1;
            }
            if (ssl_err == SSL_ERROR_SYSCALL && errno != 0) {
                set_error(error, error_len, "TLS handshake failed: %s", strerror(errno));
                return -1;
            }
            if (ssl_err == SSL_ERROR_SYSCALL && errno == 0) {
                set_error(error, error_len, "TLS handshake failed: unexpected EOF");
                return -1;
            }

            set_ssl_error(error, error_len, "TLS handshake failed");
            return -1;
        }
    }

    if (SSL_get_verify_result(conn->ssl) != X509_V_OK) {
        set_error(error, error_len, "TLS certificate verification failed");
        return -1;
    }
    return 0;
}

static ssize_t connection_read(
    struct connection *conn,
    void *buf,
    size_t len,
    char *error,
    size_t error_len
) {
    if (!conn->use_tls) {
        ssize_t n = recv(conn->fd, buf, len, 0);
        if (n < 0) {
            if (is_timeout_errno(errno)) {
                set_error(error, error_len, "Read timeout");
                return -1;
            }
            set_error(error, error_len, "Read failed: %s", strerror(errno));
            return -1;
        }
        return n;
    }

    int n = SSL_read(conn->ssl, buf, (int)len);
    if (n > 0) {
        return n;
    }

    int ssl_err = SSL_get_error(conn->ssl, n);
    if (ssl_err == SSL_ERROR_ZERO_RETURN) {
        return 0;
    }
    if ((ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) ||
        (ssl_err == SSL_ERROR_SYSCALL && is_timeout_errno(errno))) {
        set_error(error, error_len, "Read timeout");
        return -1;
    }
    if (ssl_err == SSL_ERROR_SYSCALL && errno != 0) {
        set_error(error, error_len, "Read failed: %s", strerror(errno));
        return -1;
    }
    if (ssl_err == SSL_ERROR_SYSCALL && errno == 0) {
        return 0;
    }

    set_ssl_error(error, error_len, "SSL_read failed");
    return -1;
}

static int connection_write_all(
    struct connection *conn,
    const char *buf,
    size_t len,
    char *error,
    size_t error_len
) {
    size_t sent = 0;

    while (sent < len) {
        if (!conn->use_tls) {
            ssize_t n = send(conn->fd, buf + sent, len - sent, 0);
            if (n < 0) {
                if (is_timeout_errno(errno)) {
                    set_error(error, error_len, "Write timeout");
                } else {
                    set_error(error, error_len, "Write failed: %s", strerror(errno));
                }
                return -1;
            }
            sent += (size_t)n;
            continue;
        }

        int n = SSL_write(conn->ssl, buf + sent, (int)(len - sent));
        if (n <= 0) {
            int ssl_err = SSL_get_error(conn->ssl, n);
            if ((ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) ||
                (ssl_err == SSL_ERROR_SYSCALL && is_timeout_errno(errno))) {
                set_error(error, error_len, "Write timeout");
                return -1;
            }
            if (ssl_err == SSL_ERROR_SYSCALL && errno != 0) {
                set_error(error, error_len, "Write failed: %s", strerror(errno));
                return -1;
            }
            if (ssl_err == SSL_ERROR_SYSCALL && errno == 0) {
                set_error(error, error_len, "Write failed: unexpected EOF");
                return -1;
            }
            set_ssl_error(error, error_len, "SSL_write failed");
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

static void format_host_header(const struct url_info *url, char *out, size_t out_size) {
    bool is_ipv6_literal = strchr(url->host, ':') != NULL;

    if (url->has_explicit_port) {
        if (is_ipv6_literal) {
            snprintf(out, out_size, "[%s]:%s", url->host, url->port);
        } else {
            snprintf(out, out_size, "%s:%s", url->host, url->port);
        }
        return;
    }

    if (is_ipv6_literal) {
        snprintf(out, out_size, "[%s]", url->host);
    } else {
        snprintf(out, out_size, "%s", url->host);
    }
}

/* Send a minimal HTTP/1.1 request (GET/POST). */
int send_request(
    struct connection *conn,
    const struct url_info *url,
    const char *method,
    const char *data,
    char *error,
    size_t error_len
) {
    char req[2048];
    char host_header[320];
    char body_headers[256];
    const char *verb = (method != NULL) ? method : "GET";
    size_t data_len = (data != NULL) ? strlen(data) : 0;
    bool include_body_headers = (strcasecmp(verb, "POST") == 0) || (data != NULL);
    size_t req_len;
    int n;

    format_host_header(url, host_header, sizeof(host_header));

    body_headers[0] = '\0';
    if (include_body_headers) {
        n = snprintf(
            body_headers,
            sizeof(body_headers),
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: %zu\r\n",
            data_len
        );
        if (n < 0 || (size_t)n >= sizeof(body_headers)) {
            set_error(error, error_len, "Request body headers are too large");
            return -1;
        }
    }

    n = snprintf(
        req,
        sizeof(req),
        "%s %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: curldbg/1.0\r\n"
        "Connection: close\r\n"
        "%s"
        "\r\n",
        verb,
        url->path,
        host_header,
        body_headers
    );

    if (n < 0 || (size_t)n >= sizeof(req)) {
        set_error(error, error_len, "Request is too large");
        return -1;
    }

    req_len = (size_t)n;
    if (connection_write_all(conn, req, req_len, error, error_len) != 0) {
        return -1;
    }
    if (data_len > 0) {
        return connection_write_all(conn, data, data_len, error, error_len);
    }
    return 0;
}

/* Find the end of HTTP headers in a byte buffer (\r\n\r\n). */
static char *find_header_end(char *buf, size_t len) {
    size_t i;
    if (len < 4) {
        return NULL;
    }

    for (i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return buf + i + 4;
        }
    }
    return NULL;
}

/*
 * Read response until EOF.
 * - Measures TTFB from ttfb_start to first recv()/SSL_read() data
 * - Captures first ~1KB of body (headers are stripped)
 */
int receive_response(
    struct connection *conn,
    const struct timespec *ttfb_start,
    struct response_info *out,
    char *error,
    size_t error_len
) {
    char recv_buf[4096];
    char header_buf[HEADER_MAX + 1];
    size_t header_len = 0;
    bool header_done = false;
    bool seen_first_byte = false;
    struct timespec first_byte_ts;

    memset(out, 0, sizeof(*out));

    for (;;) {
        ssize_t n = connection_read(conn, recv_buf, sizeof(recv_buf), error, error_len);
        if (n < 0) {
            return -1;
        }
        if (n == 0) {
            break;
        }

        if (!seen_first_byte) {
            if (clock_gettime(CLOCK_MONOTONIC, &first_byte_ts) != 0) {
                set_error(error, error_len, "clock_gettime failed");
                return -1;
            }
            out->ttfb_ms = ms_between(ttfb_start, &first_byte_ts);
            seen_first_byte = true;
        }

        if (!header_done) {
            if (header_len + (size_t)n >= sizeof(header_buf)) {
                set_error(error, error_len, "Response headers too large");
                return -1;
            }
            memcpy(header_buf + header_len, recv_buf, (size_t)n);
            header_len += (size_t)n;
            header_buf[header_len] = '\0';

            char *body_start = find_header_end(header_buf, header_len);
            if (body_start != NULL) {
                size_t header_bytes = (size_t)(body_start - header_buf);
                size_t body_available = header_len - header_bytes;
                size_t take = body_available;
                char headers_only[HEADER_MAX + 1];

                memcpy(headers_only, header_buf, header_bytes);
                headers_only[header_bytes] = '\0';
                parse_response_headers(headers_only, out);

                if (take > PREVIEW_BYTES - out->preview_len) {
                    take = PREVIEW_BYTES - out->preview_len;
                }
                memcpy(out->preview + out->preview_len, body_start, take);
                out->preview_len += take;
                header_done = true;
            }
            continue;
        }

        if (out->preview_len < PREVIEW_BYTES) {
            size_t take = (size_t)n;
            if (take > PREVIEW_BYTES - out->preview_len) {
                take = PREVIEW_BYTES - out->preview_len;
            }
            memcpy(out->preview + out->preview_len, recv_buf, take);
            out->preview_len += take;
        }
    }

    out->preview[out->preview_len] = '\0';
    if (!seen_first_byte) {
        out->ttfb_ms = -1.0;
    }
    return 0;
}
