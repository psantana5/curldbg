#include "curldbg.h"

#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <netinet/tcp.h>

struct run_request_task {
    const char *url;
    const struct run_options *opts;
    struct run_result *result;
    bool ok;
};

static int run_request(const char *input_url, const struct run_options *opts,
                       struct run_result *out, struct connection_state *reuse);

static void close_upload_file(FILE **file) {
    if (file != NULL && *file != NULL) { fclose(*file); *file = NULL; }
}

void free_run_result(struct run_result *result) {
    free(result->hops);
    result->hops = NULL;
    result->hop_count = 0;
}

static void *run_request_thread(void *arg) {
    struct run_request_task *task = (struct run_request_task *)arg;
    task->ok = (run_request(task->url, task->opts, task->result, NULL) == 0);
    return NULL;
}

void run_two_requests_parallel(const char *url_a, const struct run_options *opts_a,
                                       struct run_result *result_a, bool *ok_a,
                                       const char *url_b, const struct run_options *opts_b,
                                       struct run_result *result_b, bool *ok_b) {
    struct run_request_task task_a = {.url = url_a, .opts = opts_a, .result = result_a, .ok = false};
    struct run_request_task task_b = {.url = url_b, .opts = opts_b, .result = result_b, .ok = false};
    pthread_t thread_a, thread_b;
    bool thread_a_started = false, thread_b_started = false;

    if (pthread_create(&thread_a, NULL, run_request_thread, &task_a) == 0)
        thread_a_started = true;
    else
        task_a.ok = (run_request(url_a, opts_a, result_a, NULL) == 0);

    if (pthread_create(&thread_b, NULL, run_request_thread, &task_b) == 0)
        thread_b_started = true;
    else
        task_b.ok = (run_request(url_b, opts_b, result_b, NULL) == 0);

    if (thread_a_started) (void)pthread_join(thread_a, NULL);
    if (thread_b_started) (void)pthread_join(thread_b, NULL);

    *ok_a = task_a.ok;
    *ok_b = task_b.ok;
}

int setup_upload_file(const char *upload_path, FILE **upload_file,
                              size_t *upload_size, bool *chunked_upload,
                              char *error, size_t error_len) {
    *upload_file = NULL;
    *upload_size = 0;
    *chunked_upload = false;
    if (upload_path == NULL) return 0;

    if (strcmp(upload_path, "-") == 0) {
        *upload_file = stdin;
        *upload_size = 0;
        *chunked_upload = true;
        return 0;
    }
    struct stat st;
    *upload_file = fopen(upload_path, "rb");
    if (*upload_file == NULL) {
        snprintf(error, error_len, "Unable to open upload file '%s': %s",
                 upload_path, strerror(errno));
        return -1;
    }
    if (stat(upload_path, &st) != 0) {
        snprintf(error, error_len, "Unable to stat upload file '%s': %s",
                 upload_path, strerror(errno));
        fclose(*upload_file);
        *upload_file = NULL;
        return -1;
    }
    if (st.st_size < 0) {
        snprintf(error, error_len, "Upload file size is invalid");
        fclose(*upload_file);
        *upload_file = NULL;
        return -1;
    }
    if ((unsigned long long)st.st_size > (unsigned long long)SIZE_MAX) {
        snprintf(error, error_len, "Upload file is too large");
        fclose(*upload_file);
        *upload_file = NULL;
        return -1;
    }
    *upload_size = (size_t)st.st_size;
    return 0;
}

static int establish_connection(struct connection *conn,
                                 struct addrinfo **conn_addrs,
                                 char *conn_host, size_t conn_host_size,
                                 char *conn_port, size_t conn_port_size,
                                 bool *conn_use_tls,
                                 const struct url_info *url,
                                 const struct run_options *opts,
                                 struct hop_info *hop,
                                 int *preferred_family,
                                 struct connect_race_info *race_info,
                                 const struct timespec *total_start,
                                 double *connect_ms_out,
                                 double *dns_ms_out,
                                 char *error, size_t error_len) {
    *dns_ms_out = 0.0;
    *connect_ms_out = 0.0;

    bool use_proxy = (opts->proxy_host != NULL);
    bool use_unix = (opts->unix_socket_path != NULL);

    if (!use_unix) {
        struct timespec dns_start, dns_end;
        int gai_error = 0;
        int dns_timeout_ms = 5000;
        if (opts->max_time_ms > 0) {
            long rem = deadline_remaining_ms(total_start, opts->max_time_ms);
            if (rem <= 0) {
                snprintf(error, error_len, "Operation timed out after %d ms", opts->max_time_ms);
                return -1;
            }
            dns_timeout_ms = (rem < dns_timeout_ms) ? (int)rem : dns_timeout_ms;
        }
        struct addrinfo *addrs = resolve_host(url, opts->address_family,
                                               opts->resolve_entries, opts->resolve_count,
                                               dns_timeout_ms,
                                               &dns_start, &dns_end, &gai_error);
        if (addrs == NULL) {
            snprintf(error, error_len, "DNS resolution failed: %s", gai_strerror(gai_error));
            return -1;
        }
        *dns_ms_out = ms_between(&dns_start, &dns_end);
        *conn_addrs = addrs;
    }

    snprintf(conn_host, conn_host_size, "%s", url->host);
    snprintf(conn_port, conn_port_size, "%s", url->port);
    *conn_use_tls = url->use_tls;

    struct timespec connect_start, connect_end;
    clock_gettime(CLOCK_MONOTONIC, &connect_start);

    int effective_connect_ms = opts->connect_timeout_ms;
    if (opts->max_time_ms > 0) {
        long rem = deadline_remaining_ms(total_start, opts->max_time_ms);
        if (rem <= 0) {
            snprintf(error, error_len, "Operation timed out after %d ms", opts->max_time_ms);
            return -1;
        }
        if (effective_connect_ms <= 0 || (int)rem < effective_connect_ms)
            effective_connect_ms = (int)rem;
    }

    int fd;
    if (use_unix) {
        fd = connect_unix_socket(opts->unix_socket_path, error, error_len);
        clock_gettime(CLOCK_MONOTONIC, &connect_end);
        if (fd < 0) return -1;
        snprintf(hop->connected_ip, sizeof(hop->connected_ip), "%s", opts->unix_socket_path);
        hop->connected_family = AF_UNIX;
        *connect_ms_out = ms_between(&connect_start, &connect_end);
        conn->fd = fd;
        conn->use_tls = url->use_tls;
        conn->ssl = NULL;
        conn->verbose = opts->verbose;
    } else if (use_proxy) {
        struct url_info proxy_ui;
        memset(&proxy_ui, 0, sizeof(proxy_ui));
        strncpy(proxy_ui.host, opts->proxy_host, sizeof(proxy_ui.host) - 1);
        if (opts->proxy_port != NULL)
            strncpy(proxy_ui.port, opts->proxy_port, sizeof(proxy_ui.port) - 1);
        else
            strcpy(proxy_ui.port, "8080");
        freeaddrinfo(*conn_addrs);
        *conn_addrs = NULL;
        int pgai_error = 0;
        struct addrinfo *paddrs = resolve_dns_timeout(&proxy_ui, opts->address_family, &pgai_error, 5000);
        if (paddrs == NULL) {
            snprintf(error, error_len, "Proxy DNS resolution failed: %s", gai_strerror(pgai_error));
            return -1;
        }
        *conn_addrs = paddrs;
        snprintf(conn_host, conn_host_size, "%s", proxy_ui.host);
        snprintf(conn_port, conn_port_size, "%s", proxy_ui.port);
        *conn_use_tls = false;

        fd = connect_tcp(paddrs, hop->connected_ip, sizeof(hop->connected_ip),
                          &hop->connected_family, effective_connect_ms,
                          race_info, opts->happy_eyeballs, *preferred_family,
                          opts->bind_interface);
        clock_gettime(CLOCK_MONOTONIC, &connect_end);
        if (fd < 0) {
            snprintf(error, error_len, "Proxy TCP connect failed: %s", strerror(errno));
            return -1;
        }
        *connect_ms_out = (race_info->winner_connect_ms > 0.0) ? race_info->winner_connect_ms
                            : ms_between(&connect_start, &connect_end);
        conn->fd = fd;
        { int one = 1; (void)setsockopt(conn->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)); }
        conn->use_tls = false;
        conn->ssl = NULL;
        conn->verbose = opts->verbose;

        if (url->use_tls) {
            if (proxy_connect(conn, url, effective_connect_ms, error, error_len) != 0) return -1;
            if (init_tls(conn, url->host, opts->insecure_tls,
                         opts->tls_min_version, opts->tls_max_version,
                         error, error_len) != 0) return -1;
        }
    } else {
        fd = connect_tcp(*conn_addrs, hop->connected_ip, sizeof(hop->connected_ip),
                          &hop->connected_family, effective_connect_ms,
                          race_info, opts->happy_eyeballs, *preferred_family,
                          opts->bind_interface);
        clock_gettime(CLOCK_MONOTONIC, &connect_end);
        if (fd < 0) {
            snprintf(error, error_len, "TCP connect failed: %s", strerror(errno));
            return -1;
        }
        *connect_ms_out = (race_info->winner_connect_ms > 0.0) ? race_info->winner_connect_ms
                            : ms_between(&connect_start, &connect_end);
        conn->fd = fd;
        { int one = 1; (void)setsockopt(conn->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)); }
        conn->use_tls = url->use_tls;
        conn->ssl = NULL;
        conn->verbose = opts->verbose;
    }

    int effective_read_ms = opts->read_timeout_ms;
    if (effective_read_ms <= 0) effective_read_ms = 30000;
    if (opts->max_time_ms > 0) {
        long rem = deadline_remaining_ms(total_start, opts->max_time_ms);
        if (rem <= 0) {
            snprintf(error, error_len, "Operation timed out after %d ms", opts->max_time_ms);
            return -1;
        }
        if ((int)rem < effective_read_ms) effective_read_ms = (int)rem;
    }
    apply_socket_timeout(conn->fd, effective_read_ms);

    if (!use_proxy && url->use_tls) {
        if (init_tls(conn, url->host, opts->insecure_tls,
                     opts->tls_min_version, opts->tls_max_version,
                     error, error_len) != 0) return -1;
    }
    return 0;
}

bool is_connection_error(const char *error) {
    return (strncmp(error, "Write failed", 12) == 0 ||
            strncmp(error, "Read failed", 11) == 0 ||
            strncmp(error, "Write timeout", 13) == 0 ||
            strncmp(error, "Read timeout", 12) == 0);
}

static int run_request(const char *input_url, const struct run_options *opts,
                       struct run_result *out, struct connection_state *reuse) {
    /*
     * State machine for one request including all redirect hops:
     *   1. Parse URL → DNS → TCP/TLS connect → send request → receive response
     *   2. If redirect: loop (up to max_redirects), downgrade method on 301/302/303
     *   3. If connection error on reused conn: retry once with fresh connection
     *
     * Connection reuse: if 'reuse' is non-NULL, conn/addrs/host/port are carried
     * across calls (used for multi-URL batches in main.c).  The state tracks
     * whether the target host changed since the last hop so we can skip reconnect.
     */
    char current_url[2048], next_url[2048];
    int redirect_count = 0;
    FILE *upload_file = NULL;
    size_t upload_size = 0;
    bool chunked_upload = false;
    struct timespec total_start, total_end;
    int preferred_family = opts->address_family;
    struct connection_state local_state;
    struct connection_state *state;
    int rc = -1;

    if (reuse != NULL) {
        state = reuse;
    } else {
        memset(&local_state, 0, sizeof(local_state));
        local_state.conn.fd = -1;
        state = &local_state;
    }

    struct connection *conn = &state->conn;
    struct addrinfo **conn_addrs = &state->addrs;
    char *conn_host = state->host;
    char *conn_port = state->port;
    bool *conn_use_tls = &state->use_tls;

    memset(out, 0, sizeof(*out));
    out->ttfb_ms = -1.0;
    out->error[0] = '\0';

    if (strlen(input_url) >= sizeof(current_url)) {
        snprintf(out->error, sizeof(out->error), "URL too long"); return -1;
    }
    strcpy(current_url, input_url);

    if (setup_upload_file(opts->upload_path, &upload_file, &upload_size,
                          &chunked_upload, out->error, sizeof(out->error)) != 0) return -1;

    if (opts->max_redirects < 0 || opts->max_redirects > 100) {
        snprintf(out->error, sizeof(out->error), "Invalid max_redirects value");
        return -1;
    }
    out->hops = calloc((size_t)opts->max_redirects + 1, sizeof(*out->hops));
    if (out->hops == NULL) {
        snprintf(out->error, sizeof(out->error), "Out of memory");
        return -1;
    }

    if (__builtin_expect(clock_gettime(CLOCK_MONOTONIC, &total_start) != 0, 0)) die("clock_gettime");

    char method[32];
    const char *data;
    size_t data_len;
    strcpy(method, opts->method);
    data = opts->data;
    data_len = opts->data_len;

    for (;;) {
        /* Each iteration is one hop: URL → connect → send → receive → redirect? */
        struct url_info url = {0}, redirected_url = {0};
        struct connect_race_info race_info;
        struct timespec ttfb_start;
        bool can_redirect = false, reuse_connection = false;
        double hop_dns_ms = 0.0, hop_connect_ms = 0.0;

        if (opts->max_time_ms > 0) {
            long rem = deadline_remaining_ms(&total_start, opts->max_time_ms);
            if (rem <= 0) {
                snprintf(out->error, sizeof(out->error), "Operation timed out after %d ms", opts->max_time_ms);
                goto error_cleanup;
            }
        }

        if (parse_url(current_url, &url) != 0) {
            snprintf(out->error, sizeof(out->error), "Invalid URL: %.240s", current_url);
            goto error_cleanup;
        }
        if (out->hop_count >= opts->max_redirects + 1) {
            snprintf(out->error, sizeof(out->error), "Too many hops");
            goto error_cleanup;
        }
        memset(&out->hops[out->hop_count], 0, sizeof(out->hops[out->hop_count]));

        bool use_proxy = (opts->proxy_host != NULL);

        if (use_proxy) {
            reuse_connection = false;
            strcpy(out->hops[out->hop_count].connected_ip, "via-proxy");
            out->hops[out->hop_count].connected_family = AF_UNSPEC;
        } else {
            /* Reuse connection if target host/port/tls didn't change vs last hop */
            reuse_connection = (conn->fd >= 0 &&
                strcmp(url.host, conn_host) == 0 &&
                strcmp(url.port, conn_port) == 0 &&
                url.use_tls == *conn_use_tls);
            if (reuse_connection && out->hop_count > 0) {
                const struct hop_info *prev = &out->hops[out->hop_count - 1];
                strcpy(out->hops[out->hop_count].connected_ip, prev->connected_ip);
                out->hops[out->hop_count].connected_family = prev->connected_family;
            }
        }

    reconnect:
        /* Fresh connection path: close old, resolve DNS, TCP/TLS connect */
        if (!reuse_connection) {
            close_connection(conn);
            freeaddrinfo(*conn_addrs);
            *conn_addrs = NULL;
            conn_host[0] = '\0';
            conn_port[0] = '\0';
            memset(&race_info, 0, sizeof(race_info));

            if (establish_connection(conn, conn_addrs, conn_host, 256,
                                     conn_port, 16, conn_use_tls,
                                     &url, opts, &out->hops[out->hop_count],
                                     &preferred_family, &race_info, &total_start,
                                     &hop_connect_ms, &hop_dns_ms,
                                     out->error, sizeof(out->error)) != 0)
                goto error_cleanup;
        } else {
            memset(&race_info, 0, sizeof(race_info));
        }

        out->dns_ms += hop_dns_ms;
        out->connect_ms += hop_connect_ms;

        clock_gettime(CLOCK_MONOTONIC, &ttfb_start);
        if (upload_file != NULL && !chunked_upload) {
            if (fseeko(upload_file, 0, SEEK_SET) != 0) {
                snprintf(out->error, sizeof(out->error), "Failed to rewind upload file");
                goto error_cleanup;
            }
        }

        bool has_cookie_header = false, has_referer_header = false;
        unsigned int header_flags = 0;
        for (size_t i = 0; i < opts->extra_header_count; i++) {
            if (opts->extra_headers[i] == NULL) continue;
            const char *h = opts->extra_headers[i];
            char c = (char)(h[0] | 32);
            if (c == 'c') {
                if (h[1] == 'o') {
                    if (strncasecmp(h + 2, "ntent-Type:", 11) == 0)
                        header_flags |= HF_CONTENT_TYPE;
                    else if (strncasecmp(h + 2, "ntent-Length:", 13) == 0)
                        header_flags |= HF_CONTENT_LENGTH;
                    else if (strncasecmp(h + 2, "okie:", 5) == 0)
                        header_flags |= HF_COOKIE;
                }
            } else if (c == 'h' && strncasecmp(h + 1, "ost:", 4) == 0) {
                header_flags |= HF_HOST;
            } else if (c == 'a' && strncasecmp(h + 1, "ccept-Encoding:", 15) == 0) {
                header_flags |= HF_ACCEPT_ENC;
            } else if (c == 'u' && strncasecmp(h + 1, "ser-Agent:", 10) == 0) {
                header_flags |= HF_USER_AGENT;
            } else if (c == 'r' && strncasecmp(h + 1, "eferer:", 7) == 0) {
                header_flags |= HF_REFERER;
            }
        }
        has_cookie_header = (header_flags & HF_COOKIE) != 0;
        has_referer_header = (header_flags & HF_REFERER) != 0;

        char cookie_header_buf[8192] = "";
        const char *cookie_header_str = NULL;
        if (opts->cookie_jar != NULL && !has_cookie_header) {
            cookie_jar_get_header(opts->cookie_jar, url.host, url.path, url.use_tls,
                                  cookie_header_buf, sizeof(cookie_header_buf));
            if (cookie_header_buf[0] != '\0') cookie_header_str = cookie_header_buf;
        }

        char referer_header_buf[2048] = "";
        if (opts->referer != NULL && !has_referer_header) {
            int n = snprintf(referer_header_buf, sizeof(referer_header_buf), "Referer: %s", opts->referer);
            if (n < 0 || (size_t)n >= sizeof(referer_header_buf)) referer_header_buf[0] = '\0';
        }

        const char **send_headers = opts->extra_headers;
        size_t send_header_count = opts->extra_header_count;
        const char *stack_headers[32];
        size_t inject_count = (cookie_header_str != NULL ? 1 : 0) +
                              (referer_header_buf[0] != '\0' ? 1 : 0);
        if (inject_count > 0) {
            size_t total = opts->extra_header_count + inject_count;
            if (total <= sizeof(stack_headers) / sizeof(stack_headers[0])) {
                for (size_t i = 0; i < opts->extra_header_count; i++)
                    stack_headers[i] = opts->extra_headers[i];
                size_t idx = opts->extra_header_count;
                if (cookie_header_str != NULL) stack_headers[idx++] = cookie_header_str;
                if (referer_header_buf[0] != '\0') stack_headers[idx++] = referer_header_buf;
                send_headers = stack_headers;
                send_header_count = total;
            } else {
                const char **dh = malloc(total * sizeof(*dh));
                if (dh == NULL) {
                    snprintf(out->error, sizeof(out->error), "Out of memory");
                    goto error_cleanup;
                }
                for (size_t i = 0; i < opts->extra_header_count; i++)
                    dh[i] = opts->extra_headers[i];
                size_t idx = opts->extra_header_count;
                if (cookie_header_str != NULL) dh[idx++] = cookie_header_str;
                if (referer_header_buf[0] != '\0') dh[idx++] = referer_header_buf;
                send_headers = dh;
                send_header_count = total;
            }
        }

        int sr;
        bool request_retried = false;
        sr = send_request(conn, &url, method, data, data_len,
                upload_file, upload_size, send_headers, send_header_count,
                opts->basic_auth, opts->user_agent, out->error, sizeof(out->error),
                use_proxy && !url.use_tls, chunked_upload, opts->compressed,
                header_flags);
        if (sr == 0) {
            bool head_method = opts->is_head_method;
            if (receive_response(conn, &ttfb_start, &out->resp, out->error, sizeof(out->error),
                    opts->body_out, opts->follow_redirects, opts->fail_on_http_error, head_method) != 0)
                sr = -1;
        }
        /* On connection-level error with a reused socket, retry once with a fresh TCP/TLS */
        if (sr != 0 && reuse_connection && !request_retried && is_connection_error(out->error)) {
            close_connection(conn);
            freeaddrinfo(*conn_addrs);
            *conn_addrs = NULL;
            conn_host[0] = '\0';
            conn_port[0] = '\0';
            reuse_connection = false;
            request_retried = true;
            goto reconnect;
        }
        if (send_headers != opts->extra_headers && send_headers != stack_headers)
            free((void *)send_headers);

        if (sr != 0) goto error_cleanup;

        if (opts->cookie_jar != NULL && out->resp.set_cookie_len > 0) {
            char *buf = out->resp.set_cookie_buf;
            const char *line = buf;
            while (*line != '\0') {
                char *nl = strchr(line, '\n');
                if (nl != NULL) *nl = '\0';
                cookie_jar_add_set_cookie(opts->cookie_jar, line, url.host);
                if (nl == NULL) break;
                line = nl + 1;
            }
        }

        if (opts->fail_on_http_error && out->resp.status_code >= 400) {
            snprintf(out->error, sizeof(out->error), "HTTP %d", out->resp.status_code);
            goto error_cleanup;
        }
        out->ttfb_ms = out->resp.ttfb_ms;

        snprintf(out->hops[out->hop_count].host, sizeof(out->hops[out->hop_count].host), "%s", url.host);
        out->hops[out->hop_count].status_code = out->resp.status_code;
        if (!reuse_connection) {
            out->hops[out->hop_count].dns_ms = hop_dns_ms;
            out->hops[out->hop_count].tcp_ms = hop_connect_ms;
            out->hops[out->hop_count].has_loser = race_info.has_loser;
            if (race_info.has_loser) {
                snprintf(out->hops[out->hop_count].loser_ip, sizeof(out->hops[out->hop_count].loser_ip),
                         "%s", race_info.loser_ip);
                out->hops[out->hop_count].loser_family = race_info.loser_family;
                out->hops[out->hop_count].loser_connect_ms = race_info.loser_connect_ms;
            }
        }
        out->hops[out->hop_count].ttfb_ms = out->resp.ttfb_ms;

        if (is_redirect_status(out->resp.status_code) && out->resp.location[0] != '\0' &&
            build_redirect_url(out->resp.location, &url, next_url, sizeof(next_url)) == 0 &&
            parse_url(next_url, &redirected_url) == 0) {
            snprintf(out->hops[out->hop_count].redirect_to_host,
                     sizeof(out->hops[out->hop_count].redirect_to_host),
                     "%s", redirected_url.host);
            out->hops[out->hop_count].has_redirect_target = true;
            can_redirect = true;
            /* 301/302/303: downgrade to GET, per RFC 7231 */
            if (out->resp.status_code == 301 || out->resp.status_code == 302 ||
                out->resp.status_code == 303) {
                strcpy(method, "GET");
                data = NULL;
                data_len = 0;
                close_upload_file(&upload_file);
                upload_size = 0;
                chunked_upload = false;
            }
        }

        out->hop_count++;

        if (!opts->follow_redirects || !can_redirect) {
            if (format_url(&url, out->final_url, sizeof(out->final_url)) != 0)
                snprintf(out->final_url, sizeof(out->final_url), "%s", current_url);
            rc = 0;
            goto done;
        }

        if (redirect_count >= opts->max_redirects) {
            snprintf(out->error, sizeof(out->error), "Too many redirects (limit %d)", opts->max_redirects);
            goto error_cleanup;
        }

        bool same_host = (strcmp(redirected_url.host, conn_host) == 0 &&
                          strcmp(redirected_url.port, conn_port) == 0 &&
                          redirected_url.use_tls == *conn_use_tls);
        if (!same_host) {
            close_connection(conn);
            freeaddrinfo(*conn_addrs);
            *conn_addrs = NULL;
            conn_host[0] = '\0'; conn_port[0] = '\0';
        }

        strcpy(current_url, next_url);
        redirect_count++;
    }

error_cleanup:
    rc = -1;
    free(out->hops);
    out->hops = NULL;
done:
    close_upload_file(&upload_file);
    clock_gettime(CLOCK_MONOTONIC, &total_end);
    out->total_ms = ms_between(&total_start, &total_end);
    /* Connection reuse is disabled because response bodies may leave unread
     * bytes in the socket buffer, corrupting the next request. */
    close_connection(conn);
    freeaddrinfo(*conn_addrs);
    *conn_addrs = NULL;
    conn_host[0] = '\0';
    conn_port[0] = '\0';

    if (rc != 0 && out->error[0] == '\0')
        snprintf(out->error, sizeof(out->error), "Request failed");
    return rc;
}

void init_run_options(struct run_options *opts, const struct cmdline_opts *c) {
    memset(opts, 0, sizeof(*opts));
    opts->follow_redirects = c->follow_redirects;
    strcpy(opts->method, c->request_method);
    opts->data = c->request_data;
    opts->data_len = c->request_data_len;
    opts->address_family = c->address_family;
    opts->connect_timeout_ms = c->connect_timeout_ms;
    opts->read_timeout_ms = c->read_timeout_ms;
    opts->max_time_ms = c->max_time_ms;
    opts->max_redirects = c->max_redirects;
    opts->fail_on_http_error = c->fail_on_http_error;
    opts->insecure_tls = c->insecure_tls;
    opts->basic_auth = c->basic_auth;
    opts->extra_headers = c->extra_headers;
    opts->extra_header_count = c->extra_header_count;
    opts->upload_path = c->upload_path;
    opts->happy_eyeballs = c->happy_eyeballs;
    opts->verbose = c->verbose;
    opts->user_agent = c->user_agent;
    opts->cookie_data = c->cookie_data;
    opts->cookie_jar_path = c->cookie_jar_path;
    opts->resolve_entries = c->resolve_entries;
    opts->resolve_count = c->resolve_count;
    opts->referer = c->referer;
    opts->bind_interface = c->bind_interface;
    opts->tls_min_version = c->tls_min_version;
    opts->tls_max_version = c->tls_max_version;
    opts->retry_count = c->retry_count;
    opts->retry_delay_ms = c->retry_delay_ms;
    opts->compressed = c->compressed;
    opts->unix_socket_path = c->unix_socket_path;
    opts->is_head_method = (strcasecmp(opts->method, "HEAD") == 0);
}

/* --- Single request mode --- */
int run_single_request(const struct cmdline_opts *c, struct run_options *opts,
                               struct run_result *result, FILE *body_out,
                               struct connection_state *reuse) {
    struct cookie_jar *cookie_jar = opts->cookie_jar;
    init_run_options(opts, c);
    opts->body_out = body_out;
    opts->proxy_host = NULL;
    opts->proxy_port = NULL;
    opts->cookie_jar = cookie_jar;

    if (c->proxy_url != NULL) {
        struct url_info proxy_ui;
        memset(&proxy_ui, 0, sizeof(proxy_ui));
        if (parse_url(c->proxy_url, &proxy_ui) != 0) {
            fprintf(stderr, "Invalid proxy URL: %s\n", c->proxy_url); return -1;
        }
        opts->proxy_host = strdup(proxy_ui.host);
        opts->proxy_port = strdup(proxy_ui.port);
    }

    int max_attempts = 1 + opts->retry_count;
    int rc = -1;
    for (int attempt = 0; attempt < max_attempts; attempt++) {
        rc = run_request(c->input_url, opts, result, reuse);
        if (rc == 0) break;
        if (attempt + 1 < max_attempts && opts->retry_delay_ms > 0) {
            struct timespec ts = { .tv_sec = opts->retry_delay_ms / 1000,
                                   .tv_nsec = (long)(opts->retry_delay_ms % 1000) * 1000000L };
            nanosleep(&ts, NULL);
        }
    }

    free((void *)opts->proxy_host);
    free((void *)opts->proxy_port);
    if (rc != 0) {
        if (opts->retry_count > 0) {
            if ((!c->silent || c->show_error) && result->error[0] != '\0')
                fprintf(stderr, "Request failed after %d retries: %s\n", opts->retry_count, result->error);
        } else {
            if ((!c->silent || c->show_error) && result->error[0] != '\0')
                fprintf(stderr, "Request failed: %s\n", result->error);
        }
        return -1;
    }
    return 0;
}
