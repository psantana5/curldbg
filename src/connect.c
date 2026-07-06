#define _GNU_SOURCE
#include "curldbg.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <net/if.h>
#include <arpa/inet.h>

#define HAPPY_EYEBALLS_DELAY_MS 25

static int bind_to_interface(int fd, const char *bind_interface) {
    if (bind_interface == NULL) return 0;

    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, bind_interface, &a4) == 1) {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr = a4;
        sin.sin_port = 0;
        if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) != 0) return -1;
        return 0;
    }
    if (inet_pton(AF_INET6, bind_interface, &a6) == 1) {
        struct sockaddr_in6 sin6;
        memset(&sin6, 0, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_addr = a6;
        sin6.sin6_port = 0;
        if (bind(fd, (struct sockaddr *)&sin6, sizeof(sin6)) != 0) return -1;
        return 0;
    }
#ifdef SO_BINDTODEVICE
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, bind_interface, strlen(bind_interface)) != 0)
        return -1;
#endif
    return 0;
}

static int connect_with_timeout(int fd, const struct sockaddr *addr, socklen_t addrlen, int timeout_ms) {
    int flags;
    int rc;

    if (timeout_ms <= 0) timeout_ms = 30000;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) return -1;

    rc = connect(fd, addr, addrlen);
    if (rc == 0) {
        if (fcntl(fd, F_SETFL, flags) != 0) return -1;
        return 0;
    }
    if (errno != EINPROGRESS) {
        (void)fcntl(fd, F_SETFL, flags);
        return -1;
    }

    for (;;) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        int poll_rc = poll(&pfd, 1, timeout_ms);
        if (poll_rc < 0) {
            if (errno == EINTR) continue;
            (void)fcntl(fd, F_SETFL, flags);
            return -1;
        }
        if (poll_rc == 0) { errno = ETIMEDOUT; (void)fcntl(fd, F_SETFL, flags); return -1; }

        int so_error = 0;
        socklen_t so_error_len = sizeof(so_error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len) != 0) {
            (void)fcntl(fd, F_SETFL, flags);
            return -1;
        }
        if (so_error != 0) { errno = so_error; (void)fcntl(fd, F_SETFL, flags); return -1; }
        break;
    }

    if (fcntl(fd, F_SETFL, flags) != 0) return -1;
    return 0;
}

static int connect_tcp_sequential(
    const struct addrinfo *addrs,
    char *connected_ip, size_t connected_ip_size,
    int *connected_family,
    int connect_timeout_ms,
    struct connect_race_info *race_info,
    const char *bind_interface
) {
    const struct addrinfo *ai;
    int last_errno = 0;
    clear_race_info(race_info);

    for (ai = addrs; ai != NULL; ai = ai->ai_next) {
        struct timespec start_ts, end_ts;
        int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) { last_errno = errno; continue; }

        if (bind_to_interface(fd, bind_interface) != 0) { last_errno = errno; close(fd); continue; }

        clock_gettime(CLOCK_MONOTONIC, &start_ts);
        if (connect_with_timeout(fd, ai->ai_addr, ai->ai_addrlen, connect_timeout_ms) == 0) {
            clock_gettime(CLOCK_MONOTONIC, &end_ts);
            if (race_info != NULL)
                race_info->winner_connect_ms = ms_between(&start_ts, &end_ts);
            fill_connected_endpoint(ai, connected_ip, connected_ip_size, connected_family);
            return fd;
        }
        clock_gettime(CLOCK_MONOTONIC, &end_ts);
        last_errno = errno;
        close(fd);
    }

    errno = (last_errno != 0) ? last_errno : ECONNREFUSED;
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
    char *connected_ip, size_t connected_ip_size,
    int *connected_family,
    int connect_timeout_ms,
    struct connect_race_info *race_info,
    const char *bind_interface
) {
    const struct addrinfo *ai;
    size_t total = 0, v4_total = 0, v6_total = 0;
    const struct addrinfo **v4 = NULL, **v6 = NULL;
    struct he_attempt *attempts = NULL;
    struct pollfd *pfds = NULL;
    size_t *pfd_to_attempt = NULL;
    size_t next_index = 0;
    int active_count = 0, last_errno = 0;
    long long next_start_ms;
    int winner_fd = -1;
    size_t winner_idx = 0;
    bool have_winner = false;
    long long race_start_ms;

    for (ai = addrs; ai != NULL; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) v4_total++, total++;
        else if (ai->ai_family == AF_INET6) v6_total++, total++;
    }

    if (v4_total == 0 || v6_total == 0 || total == 0) {
        return connect_tcp_sequential(addrs, connected_ip, connected_ip_size,
                                        connected_family, connect_timeout_ms, race_info, bind_interface);
    }

    clear_race_info(race_info);
    {
        size_t sz_v4 = v4_total * sizeof(*v4);
        size_t sz_v6 = v6_total * sizeof(*v6);
        size_t sz_att = total * sizeof(*attempts);
        size_t sz_pfd = total * sizeof(*pfds);
        size_t sz_idx = total * sizeof(*pfd_to_attempt);
        char *mem = calloc(1, sz_v4 + sz_v6 + sz_att + sz_pfd + sz_idx);
        if (mem == NULL) { errno = ENOMEM; return -1; }
        v4 = (const struct addrinfo **)mem;
        v6 = (const struct addrinfo **)(mem + sz_v4);
        attempts = (struct he_attempt *)(mem + sz_v4 + sz_v6);
        pfds = (struct pollfd *)(mem + sz_v4 + sz_v6 + sz_att);
        pfd_to_attempt = (size_t *)(mem + sz_v4 + sz_v6 + sz_att + sz_pfd);
    }

    {
        size_t i4 = 0, i6 = 0, idx = 0;
        for (ai = addrs; ai != NULL; ai = ai->ai_next) {
            if (ai->ai_family == AF_INET) v4[i4++] = ai;
            else if (ai->ai_family == AF_INET6) v6[i6++] = ai;
        }
        i4 = 0; i6 = 0;
        while (i4 < v4_total || i6 < v6_total) {
            if (i6 < v6_total) { attempts[idx].ai = v6[i6++]; attempts[idx].fd = -1; idx++; }
            if (i4 < v4_total) { attempts[idx].ai = v4[i4++]; attempts[idx].fd = -1; idx++; }
        }
    }

    race_start_ms = now_ms_monotonic();
    next_start_ms = race_start_ms;

    for (;;) {
        long long now = now_ms_monotonic();

        if (next_index < total && now >= next_start_ms) {
            int fd = socket(attempts[next_index].ai->ai_family, SOCK_STREAM, attempts[next_index].ai->ai_protocol);
            if (fd >= 0) {
                if (bind_to_interface(fd, bind_interface) != 0) { last_errno = errno; close(fd); }
                else if (set_nonblocking(fd, true) != 0) {
                    last_errno = errno; close(fd);
                } else {
                    int rc = connect(fd, attempts[next_index].ai->ai_addr, attempts[next_index].ai->ai_addrlen);
                    if (rc == 0) {
                        attempts[next_index].fd = fd;
                        attempts[next_index].finished = true;
                        attempts[next_index].success = true;
                        attempts[next_index].connect_ms = (double)(now - race_start_ms);
                        have_winner = true; winner_fd = fd; winner_idx = next_index;
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
            if (next_index >= total) break;
            if (next_start_ms > now) (void)poll(NULL, 0, (int)(next_start_ms - now));
            continue;
        }

        {
            nfds_t nfds = 0;
            int poll_timeout = -1;

            if (next_index < total && next_start_ms > now)
                poll_timeout = (int)(next_start_ms - now);
            else if (next_index < total)
                poll_timeout = 0;

            if (connect_timeout_ms > 0) {
                for (size_t i = 0; i < total; i++) {
                    if (!attempts[i].active) continue;
                    long long remain = (attempts[i].started_ms + connect_timeout_ms) - now;
                    int remain_ms = (remain <= 0) ? 0 : (int)remain;
                    if (poll_timeout < 0 || remain_ms < poll_timeout) poll_timeout = remain_ms;
                }
            }
            if (poll_timeout < 0) {
                int nearest = -1;
                for (size_t i = 0; i < total; i++) {
                    if (!attempts[i].active) continue;
                    long long remain = (attempts[i].started_ms + 30000) - now;
                    int remain_ms = (remain <= 0) ? 0 : (int)remain;
                    if (nearest < 0 || remain_ms < nearest) nearest = remain_ms;
                }
                poll_timeout = (nearest >= 0) ? nearest : 30000;
            }

            for (size_t i = 0; i < total; i++) {
                if (!attempts[i].active) continue;
                pfd_to_attempt[nfds] = i;
                pfds[nfds].fd = attempts[i].fd;
                pfds[nfds].events = POLLOUT;
                pfds[nfds].revents = 0;
                nfds++;
            }

            if (poll(pfds, nfds, poll_timeout) < 0) {
                if (errno == EINTR) continue;
                last_errno = errno; break;
            }

            now = now_ms_monotonic();

            for (nfds_t pidx = 0; pidx < nfds; pidx++) {
                if ((pfds[pidx].revents & (POLLOUT | POLLERR | POLLHUP)) == 0) continue;
                size_t i = pfd_to_attempt[pidx];
                int so_error = 0;
                socklen_t so_len = sizeof(so_error);
                if (getsockopt(attempts[i].fd, SOL_SOCKET, SO_ERROR, &so_error, &so_len) != 0)
                    so_error = errno;

                if (so_error == 0) {
                    attempts[i].finished = true; attempts[i].success = true;
                    attempts[i].connect_ms = (double)(now - race_start_ms);
                    have_winner = true; winner_fd = attempts[i].fd; winner_idx = i;
                    attempts[i].active = false; active_count--;
                } else {
                    last_errno = so_error;
                    attempts[i].finished = true; attempts[i].success = false;
                    attempts[i].connect_ms = (double)(now - race_start_ms);
                    close(attempts[i].fd); attempts[i].fd = -1;
                    attempts[i].active = false; active_count--;
                }
            }

            if (!have_winner && connect_timeout_ms > 0) {
                for (size_t i = 0; i < total; i++) {
                    if (!attempts[i].active) continue;
                    if (now - attempts[i].started_ms >= connect_timeout_ms) {
                        last_errno = ETIMEDOUT;
                        attempts[i].finished = true; attempts[i].success = false;
                        attempts[i].connect_ms = (double)(now - race_start_ms);
                        close(attempts[i].fd); attempts[i].fd = -1;
                        attempts[i].active = false; active_count--;
                    }
                }
            }
        }

        if (have_winner) break;
    }

    if (have_winner) {
        long long now = now_ms_monotonic();
        size_t loser_idx = total;
        if (now < race_start_ms) now = race_start_ms;

        for (size_t i = 0; i < total; i++) {
            if (i == winner_idx || !attempts[i].active || attempts[i].fd < 0) continue;
            struct pollfd pfd;
            memset(&pfd, 0, sizeof(pfd));
            pfd.fd = attempts[i].fd;
            pfd.events = POLLOUT;
            int rc = poll(&pfd, 1, 0);
            if (rc <= 0 || !(pfd.revents & (POLLOUT | POLLERR | POLLHUP | POLLNVAL))) continue;
            int so_error = 0;
            socklen_t so_len = sizeof(so_error);
            if (getsockopt(attempts[i].fd, SOL_SOCKET, SO_ERROR, &so_error, &so_len) != 0)
                so_error = errno;
            attempts[i].finished = true;
            attempts[i].connect_ms = (double)(now - race_start_ms);
            attempts[i].active = false;
            attempts[i].success = (so_error == 0);
        }

        if (race_info != NULL)
            race_info->winner_connect_ms = attempts[winner_idx].connect_ms;

        for (size_t i = 0; i < total; i++) {
            if (i == winner_idx || !attempts[i].finished || !attempts[i].success) continue;
            if (loser_idx == total || attempts[i].connect_ms > attempts[loser_idx].connect_ms)
                loser_idx = i;
        }

        if (race_info != NULL && loser_idx != total) {
            race_info->has_loser = true;
            race_info->loser_connect_ms = attempts[loser_idx].connect_ms;
            fill_connected_endpoint(attempts[loser_idx].ai, race_info->loser_ip,
                                     sizeof(race_info->loser_ip), &race_info->loser_family);
        }

        for (size_t i = 0; i < total; i++) {
            if (i == winner_idx) continue;
            if (attempts[i].fd >= 0) { close(attempts[i].fd); attempts[i].fd = -1; }
        }

        if (set_nonblocking(winner_fd, false) != 0) {
            last_errno = errno; close(winner_fd); winner_fd = -1;
        } else {
            fill_connected_endpoint(attempts[winner_idx].ai, connected_ip, connected_ip_size, connected_family);
        }
    }

    free(v4);
    if (winner_fd >= 0) return winner_fd;
    errno = (last_errno != 0) ? last_errno : ECONNREFUSED;
    return -1;
}

static int connect_tcp_preferred_first(
    const struct addrinfo *addrs,
    char *connected_ip, size_t connected_ip_size,
    int *connected_family,
    int connect_timeout_ms,
    struct connect_race_info *race_info,
    int preferred_family,
    const char *bind_interface
) {
    const struct addrinfo *ai;
    int last_errno = 0;
    int per_attempt_ms = (connect_timeout_ms > 0) ? connect_timeout_ms : 5000;

    clear_race_info(race_info);

    for (ai = addrs; ai != NULL; ai = ai->ai_next) {
        if (ai->ai_family != preferred_family) continue;
        struct timespec start_ts, end_ts;
        int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) { last_errno = errno; continue; }
        if (bind_to_interface(fd, bind_interface) != 0) { last_errno = errno; close(fd); continue; }

        clock_gettime(CLOCK_MONOTONIC, &start_ts);
        if (connect_with_timeout(fd, ai->ai_addr, ai->ai_addrlen, per_attempt_ms) == 0) {
            clock_gettime(CLOCK_MONOTONIC, &end_ts);
            if (race_info != NULL) race_info->winner_connect_ms = ms_between(&start_ts, &end_ts);
            fill_connected_endpoint(ai, connected_ip, connected_ip_size, connected_family);
            return fd;
        }
        last_errno = errno;
        close(fd);
    }

    errno = (last_errno != 0) ? last_errno : ECONNREFUSED;
    return -1;
}

/* Try each resolved address until one connect() succeeds. */
int connect_tcp(
    const struct addrinfo *addrs,
    char *connected_ip, size_t connected_ip_size,
    int *connected_family,
    int connect_timeout_ms,
    struct connect_race_info *race_info,
    bool happy_eyeballs,
    int preferred_family,
    const char *bind_interface
) {
    if (preferred_family != AF_UNSPEC)
        return connect_tcp_preferred_first(addrs, connected_ip, connected_ip_size, connected_family,
                                            connect_timeout_ms, race_info, preferred_family, bind_interface);
    if (!happy_eyeballs)
        return connect_tcp_sequential(addrs, connected_ip, connected_ip_size, connected_family,
                                       connect_timeout_ms, race_info, bind_interface);
    return connect_tcp_happy_eyeballs(addrs, connected_ip, connected_ip_size, connected_family,
                                       connect_timeout_ms, race_info, bind_interface);
}

void apply_socket_timeout(int fd, int timeout_ms) {
    struct timeval tv;
    if (timeout_ms <= 0) return;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

int connect_unix_socket(const char *path, char *error, size_t error_len) {
    struct sockaddr_un addr;
    if (strlen(path) >= sizeof(addr.sun_path)) {
        set_error(error, error_len, "Unix socket path too long");
        return -1;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        set_error(error, error_len, "Failed to create Unix socket: %s", strerror(errno));
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        int saved = errno;
        close(fd);
        set_error(error, error_len, "Failed to connect Unix socket '%s': %s", path, strerror(saved));
        return -1;
    }
    return fd;
}

void close_connection(struct connection *conn) {
    if (conn->ssl != NULL) {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }
}

ssize_t connection_read(struct connection *conn, void *buf, size_t len, char *error, size_t error_len) {
    if (!conn->use_tls) {
        ssize_t n = recv(conn->fd, buf, len, 0);
        if (n < 0) {
            if (is_timeout_errno(errno)) { set_error(error, error_len, "Read timeout"); return -1; }
            set_error(error, error_len, "Read failed: %s", strerror(errno)); return -1;
        }
        return n;
    }

    int n = SSL_read(conn->ssl, buf, (int)len);
    if (n > 0) return n;

    int ssl_err = SSL_get_error(conn->ssl, n);
    if (ssl_err == SSL_ERROR_ZERO_RETURN) return 0;
    if ((ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) ||
        (ssl_err == SSL_ERROR_SYSCALL && is_timeout_errno(errno))) {
        set_error(error, error_len, "Read timeout"); return -1;
    }
    if (ssl_err == SSL_ERROR_SYSCALL && errno != 0) {
        set_error(error, error_len, "Read failed: %s", strerror(errno)); return -1;
    }
    if (ssl_err == SSL_ERROR_SYSCALL && errno == 0) return 0;

    set_ssl_error(error, error_len, "SSL_read failed"); return -1;
}

int connection_write_all(struct connection *conn, const char *buf, size_t len, char *error, size_t error_len) {
    size_t sent = 0;
    while (sent < len) {
        if (!conn->use_tls) {
            ssize_t n = send(conn->fd, buf + sent, len - sent, 0);
            if (n < 0) {
                if (is_timeout_errno(errno)) set_error(error, error_len, "Write timeout");
                else set_error(error, error_len, "Write failed: %s", strerror(errno));
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
                set_error(error, error_len, "Write timeout"); return -1;
            }
            if (ssl_err == SSL_ERROR_SYSCALL && errno != 0) {
                set_error(error, error_len, "Write failed: %s", strerror(errno)); return -1;
            }
            if (ssl_err == SSL_ERROR_SYSCALL && errno == 0) {
                set_error(error, error_len, "Write failed: unexpected EOF"); return -1;
            }
            set_ssl_error(error, error_len, "SSL_write failed"); return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

int connection_writev_all(struct connection *conn, const struct iovec *iov, int iovcnt,
                          char *error, size_t error_len) {
    if (iovcnt <= 0) return 0;

    if (conn->use_tls) {
        for (int i = 0; i < iovcnt; i++) {
            if (iov[i].iov_len == 0) continue;
            if (connection_write_all(conn, iov[i].iov_base, iov[i].iov_len, error, error_len) != 0)
                return -1;
        }
        return 0;
    }

    size_t total = 0;
    for (int i = 0; i < iovcnt; i++) total += iov[i].iov_len;
    if (total == 0) return 0;

    struct iovec local_iov[8];
    struct iovec *iov_copy = local_iov;
    struct iovec *iov_orig = iov_copy;
    if (iovcnt > 8) {
        iov_copy = malloc((size_t)iovcnt * sizeof(*iov_copy));
        if (iov_copy == NULL) {
            set_error(error, error_len, "Out of memory for writev");
            return -1;
        }
        iov_orig = iov_copy;
    }
    memcpy(iov_copy, iov, (size_t)iovcnt * sizeof(*iov_copy));
    int remaining = iovcnt;

    size_t sent = 0;
    while (sent < total) {
        ssize_t n = writev(conn->fd, iov_copy, remaining);
        if (n < 0) {
            if (iov_orig != local_iov) free(iov_orig);
            if (is_timeout_errno(errno)) set_error(error, error_len, "Write timeout");
            else set_error(error, error_len, "Write failed: %s", strerror(errno));
            return -1;
        }
        sent += (size_t)n;
        ssize_t consumed = n;
        while (remaining > 0 && consumed >= (ssize_t)iov_copy[0].iov_len) {
            consumed -= (ssize_t)iov_copy[0].iov_len;
            iov_copy++;
            remaining--;
        }
        if (remaining > 0 && consumed > 0) {
            iov_copy[0].iov_base = (char *)iov_copy[0].iov_base + consumed;
            iov_copy[0].iov_len -= (size_t)consumed;
        }
    }

    if (iov_orig != local_iov) free(iov_orig);
    return 0;
}
