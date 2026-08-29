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
    free(result->resp.body_buf);
    result->resp.body_buf = NULL;
    result->resp.body_len = 0;
    result->resp.body_cap = 0;
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
    if (fstat(fileno(*upload_file), &st) != 0) {
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
                                  const int *preferred_family,
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
                                               opts->dns_cache, dns_timeout_ms,
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
        if (fd < 0) {
            *connect_ms_out = ms_between(&connect_start, &connect_end);
            return -1;
        }
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
            safe_strlcpy(proxy_ui.port, "8080", sizeof(proxy_ui.port));
        freeaddrinfo(*conn_addrs);
        *conn_addrs = NULL;
        int pgai_error = 0;
        struct addrinfo *paddrs = resolve_dns_timeout(&proxy_ui, opts->address_family,
                                                       opts->dns_cache, &pgai_error, 5000);
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
            *connect_ms_out = (race_info->winner_connect_ms > 0.0) ? race_info->winner_connect_ms
                               : ms_between(&connect_start, &connect_end);
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
                         &opts->tls_params, opts->tls_ctx, error, error_len) != 0) return -1;
            if (http2_negotiated(conn)) {
                if (http2_init_connection(conn, error, error_len) != 0) return -1;
            }
        }
    } else {
        fd = connect_tcp(*conn_addrs, hop->connected_ip, sizeof(hop->connected_ip),
                          &hop->connected_family, effective_connect_ms,
                          race_info, opts->happy_eyeballs, *preferred_family,
                          opts->bind_interface);
        clock_gettime(CLOCK_MONOTONIC, &connect_end);
        if (fd < 0) {
            *connect_ms_out = (race_info->winner_connect_ms > 0.0) ? race_info->winner_connect_ms
                               : ms_between(&connect_start, &connect_end);
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
    if (apply_socket_timeout(conn->fd, effective_read_ms) != 0) {
        snprintf(error, error_len, "Failed to set socket read timeout");
        return -1;
    }

    if (!use_proxy && url->use_tls) {
        if (init_tls(conn, url->host, opts->insecure_tls,
                     opts->tls_min_version, opts->tls_max_version,
                     &opts->tls_params, opts->tls_ctx, error, error_len) != 0) return -1;
        if (http2_negotiated(conn)) {
            if (http2_init_connection(conn, error, error_len) != 0) return -1;
        }
    }
    conn->last_errno = 0;
    return 0;
}

bool is_connection_error(const struct connection *conn) {
    if (conn == NULL) return false;
    switch (conn->last_errno) {
        case ECONNRESET:
        case EPIPE:
        case ETIMEDOUT:
        case ECONNREFUSED:
        case ENETUNREACH:
        case EHOSTUNREACH:
            return true;
        default:
            return false;
    }
}

/* ================================================================
 * built_headers — owns cookie/referer injection + stack/heap array
 * ================================================================ */
struct built_headers {
    const char **headers;
    size_t count;
    unsigned int flags;
    char cookie_buf[8192];
    char referer_buf[2048];
    const char *stack_headers[32];
    bool heap_owned;
};

static void free_built_headers(struct built_headers *h) {
    if (h->heap_owned) free((void *)h->headers);
}

/* Append a header pointer, growing to a heap array when the inline stack
 * buffer (or an externally-owned array such as cmdline_opts.extra_headers)
 * has no room. Never reallocs memory it does not own. */
static int built_headers_append(struct built_headers *h, const char *header) {
    size_t max_s = sizeof(h->stack_headers) / sizeof(h->stack_headers[0]);
    size_t new_count = h->count + 1;
    if (!h->heap_owned && new_count <= max_s) {
        for (size_t i = 0; i < h->count; i++)
            h->stack_headers[i] = h->headers ? h->headers[i] : NULL;
        h->headers = h->stack_headers;
        h->stack_headers[h->count] = header;
        h->count = new_count;
        return 0;
    }
    if (h->heap_owned) {
        const char **nh = realloc((void *)h->headers, new_count * sizeof(*nh));
        if (nh == NULL) return -1;
        h->headers = nh;
    } else {
        const char **nh = malloc(new_count * sizeof(*nh));
        if (nh == NULL) return -1;
        for (size_t i = 0; i < h->count; i++)
            nh[i] = h->headers ? h->headers[i] : NULL;
        h->headers = nh;
        h->heap_owned = true;
    }
    h->headers[h->count] = header;
    h->count = new_count;
    return 0;
}

static int build_request_headers(const struct run_options *opts,
                                  const struct url_info *url,
                                  struct built_headers *hdrs,
                                  char *error, size_t error_len) {
    memset(hdrs, 0, sizeof(*hdrs));

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
    hdrs->flags = header_flags;

    const char *cookie_header_str = NULL;
    if (opts->cookie_jar != NULL && !has_cookie_header) {
        cookie_jar_get_header(opts->cookie_jar, url->host, url->path, url->use_tls,
                               hdrs->cookie_buf, sizeof(hdrs->cookie_buf));
        if (hdrs->cookie_buf[0] != '\0') cookie_header_str = hdrs->cookie_buf;
    }

    if (opts->referer != NULL && !has_referer_header) {
        int n = snprintf(hdrs->referer_buf, sizeof(hdrs->referer_buf),
                         "Referer: %s", opts->referer);
        if (n < 0 || (size_t)n >= sizeof(hdrs->referer_buf))
            hdrs->referer_buf[0] = '\0';
    }

    hdrs->headers = opts->extra_headers;
    hdrs->count = opts->extra_header_count;

    size_t inject_count = (size_t)(cookie_header_str != NULL ? 1 : 0) +
                           (size_t)(hdrs->referer_buf[0] != '\0' ? 1 : 0);
    if (inject_count == 0) return 0;

    size_t total = opts->extra_header_count + inject_count;
    size_t max_stack = sizeof(hdrs->stack_headers) / sizeof(hdrs->stack_headers[0]);

    if (total <= max_stack) {
        hdrs->headers = hdrs->stack_headers;
        hdrs->heap_owned = false;
    } else {
        const char **dh = malloc(total * sizeof(*dh));
        if (dh == NULL) {
            snprintf(error, error_len, "Out of memory");
            return -1;
        }
        hdrs->headers = dh;
        hdrs->heap_owned = true;
    }
    for (size_t i = 0; i < opts->extra_header_count; i++)
        hdrs->headers[i] = opts->extra_headers[i];
    hdrs->count = total;
    size_t idx = opts->extra_header_count;
    if (cookie_header_str != NULL) hdrs->headers[idx++] = cookie_header_str;
    if (hdrs->referer_buf[0] != '\0') hdrs->headers[idx++] = hdrs->referer_buf;
    return 0;
}

/* Returns 0 on success, -1 on failure (error already set in out->error).
 * May append h2 content-type/length pseudo-headers to hdrs->stack_headers. */
static int dispatch_request(struct connection *conn, const struct url_info *url,
                             const char *method, const char *data, size_t data_len,
                             FILE *upload_file, size_t upload_size,
                             bool chunked_upload, struct built_headers *hdrs,
                             bool use_proxy, const struct run_options *opts,
                             struct run_result *out, const struct timespec *ttfb_start) {
    if (opts->force_http_version == 1 && http2_negotiated(conn)) {
        snprintf(out->error, sizeof(out->error),
                 "Server negotiated HTTP/2 but --http1.1 was forced");
        return -1;
    }
    if (opts->force_http_version == 2 && conn->use_tls && !http2_negotiated(conn)) {
        snprintf(out->error, sizeof(out->error),
                 "Server did not negotiate HTTP/2 but --http2 was forced");
        return -1;
    }

    if (http2_negotiated(conn)) {
        snprintf(out->resp.http_version, sizeof(out->resp.http_version), "HTTP/2");
        const char *effective_auth = opts->basic_auth;
        if (effective_auth == NULL || effective_auth[0] == '\0') {
            if (url->user[0] != '\0') effective_auth = url->user;
        }

        bool has_ct = (hdrs->flags & HF_CONTENT_TYPE) != 0;
        bool has_cl = (hdrs->flags & HF_CONTENT_LENGTH) != 0;
        if ((data != NULL && data_len > 0) || upload_file != NULL) {
            char ct_buf[128] = "", cl_buf[64] = "";
            size_t body_len = (upload_file != NULL) ? upload_size : data_len;
            if (!has_ct) {
                const char *ct = (upload_file != NULL) ? "application/octet-stream"
                                                         : "application/x-www-form-urlencoded";
                int n = snprintf(ct_buf, sizeof(ct_buf), "content-type: %s", ct);
                if (n <= 0 || (size_t)n >= sizeof(ct_buf)) ct_buf[0] = '\0';
            }
            if (!has_cl) {
                int n = snprintf(cl_buf, sizeof(cl_buf), "content-length: %zu", body_len);
                if (n <= 0 || (size_t)n >= sizeof(cl_buf)) cl_buf[0] = '\0';
            }
            if (ct_buf[0] != '\0' && built_headers_append(hdrs, ct_buf) != 0) {
                snprintf(out->error, sizeof(out->error), "Out of memory");
                return -1;
            }
            if (cl_buf[0] != '\0' && built_headers_append(hdrs, cl_buf) != 0) {
                snprintf(out->error, sizeof(out->error), "Out of memory");
                return -1;
            }
        }

        uint32_t sid = http2_send_request(conn, url, method, data, data_len,
                                           hdrs->headers, hdrs->count,
                                           opts->user_agent, effective_auth,
                                           out->error, sizeof(out->error));
        if (sid == 0) return -1;
        if (http2_receive_response(conn, sid, &out->resp, ttfb_start,
                                    opts->body_out, out->error, sizeof(out->error)) != 0)
            return -1;
        return 0;
    }

    if (send_request(conn, url, method, data, data_len,
                      upload_file, upload_size, hdrs->headers, hdrs->count,
                      opts->basic_auth, opts->user_agent, out->error, sizeof(out->error),
                      use_proxy && !url->use_tls, chunked_upload, opts->compressed,
                      hdrs->flags) != 0)
        return -1;

    snprintf(out->resp.http_version, sizeof(out->resp.http_version), "HTTP/1.1");
    if (receive_response(conn, ttfb_start, &out->resp, out->error, sizeof(out->error),
                          opts->body_out, opts->follow_redirects,
                          opts->fail_on_http_error, opts->is_head_method) != 0)
        return -1;
    return 0;
}

static void update_hop_record(struct hop_info *hop, const struct url_info *url,
                               const struct run_result *out, bool reuse_connection,
                               double hop_dns_ms, double hop_connect_ms,
                               const struct connect_race_info *race_info) {
    snprintf(hop->host, sizeof(hop->host), "%s", url->host);
    hop->status_code = out->resp.status_code;
    if (!reuse_connection) {
        hop->dns_ms = hop_dns_ms;
        hop->tcp_ms = hop_connect_ms;
        hop->has_loser = race_info->has_loser;
        if (race_info->has_loser) {
            snprintf(hop->loser_ip, sizeof(hop->loser_ip), "%s", race_info->loser_ip);
            hop->loser_family = race_info->loser_family;
            hop->loser_connect_ms = race_info->loser_connect_ms;
        }
    }
    hop->ttfb_ms = out->resp.ttfb_ms;
}

struct redirect_plan {
    bool should_redirect;
    bool downgrade_to_get;
    char next_url[2048];
    struct url_info redirected_url;
};

static bool plan_redirect(const struct response_info *resp,
                           const struct url_info *url,
                           struct redirect_plan *plan) {
    memset(plan, 0, sizeof(*plan));
    if (!is_redirect_status(resp->status_code) || resp->location[0] == '\0')
        return false;
    if (build_redirect_url(resp->location, url, plan->next_url, sizeof(plan->next_url)) != 0)
        return false;
    if (parse_url(plan->next_url, &plan->redirected_url) != 0)
        return false;
    plan->should_redirect = true;
    plan->downgrade_to_get = (resp->status_code == 301 || resp->status_code == 302 ||
                              resp->status_code == 303);
    return true;
}

static int run_request(const char *input_url, const struct run_options *opts,
                       struct run_result *out, struct connection_state *reuse) {
    char current_url[2048];
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
    out->is_head = opts->is_head_method;

    if (strlen(input_url) >= sizeof(current_url)) {
        snprintf(out->error, sizeof(out->error), "URL too long"); return -1;
    }
    safe_strlcpy(current_url, input_url, sizeof(current_url));

    if (setup_upload_file(opts->upload_path, &upload_file, &upload_size,
                          &chunked_upload, out->error, sizeof(out->error)) != 0) return -1;

    if (opts->max_redirects < 0 || opts->max_redirects > 100) {
        snprintf(out->error, sizeof(out->error), "Invalid max_redirects value");
        goto error_cleanup;
    }
    out->hops = calloc((size_t)opts->max_redirects + 1, sizeof(*out->hops));
    if (out->hops == NULL) {
        snprintf(out->error, sizeof(out->error), "Out of memory");
        goto error_cleanup;
    }

    if (__builtin_expect(clock_gettime(CLOCK_MONOTONIC, &total_start) != 0, 0)) die("clock_gettime");

    char method[32];
    const char *data;
    size_t data_len;
    safe_strlcpy(method, opts->method, sizeof(method));
    data = opts->data;
    data_len = opts->data_len;

    for (;;) {
        /* --- outer loop: one iteration per hop --- */
        struct url_info url = {0};
        struct connect_race_info race_info;
        struct timespec ttfb_start;
        double hop_dns_ms = 0.0, hop_connect_ms = 0.0;
        bool reuse_connection = false;

        if (opts->max_time_ms > 0) {
            long rem = deadline_remaining_ms(&total_start, opts->max_time_ms);
            if (rem <= 0) {
                snprintf(out->error, sizeof(out->error),
                         "Operation timed out after %d ms", opts->max_time_ms);
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
            safe_strlcpy(out->hops[out->hop_count].connected_ip, "via-proxy",
                         sizeof(out->hops[0].connected_ip));
            out->hops[out->hop_count].connected_family = AF_UNSPEC;
        } else {
            reuse_connection = (conn->fd >= 0 &&
                strcmp(url.host, conn_host) == 0 &&
                strcmp(url.port, conn_port) == 0 &&
                url.use_tls == *conn_use_tls);
            if (reuse_connection && out->hop_count > 0) {
                const struct hop_info *prev = &out->hops[out->hop_count - 1];
                safe_strlcpy(out->hops[out->hop_count].connected_ip,
                             prev->connected_ip, sizeof(out->hops[0].connected_ip));
                out->hops[out->hop_count].connected_family = prev->connected_family;
            }
        }

        /* === inner loop: hop attempt, retried at most once on connection error === */
        bool need_fresh_connection = !reuse_connection;
        bool retried_this_hop = false;
        int sr;

        for (;;) {
            struct built_headers hdrs;

            if (need_fresh_connection) {
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
                                         out->error, sizeof(out->error)) != 0) {
                    out->dns_ms += hop_dns_ms;
                    out->connect_ms += hop_connect_ms;
                    goto error_cleanup;
                }
            } else {
                memset(&race_info, 0, sizeof(race_info));
            }

            out->dns_ms += hop_dns_ms;
            out->connect_ms += hop_connect_ms;

            if (build_request_headers(opts, &url, &hdrs,
                                      out->error, sizeof(out->error)) != 0) {
                sr = -1; goto dispatch_cleanup;
            }

            clock_gettime(CLOCK_MONOTONIC, &ttfb_start);
            if (upload_file != NULL && !chunked_upload) {
                if (fseeko(upload_file, 0, SEEK_SET) != 0) {
                    snprintf(out->error, sizeof(out->error),
                             "Failed to rewind upload file");
                    sr = -1; goto dispatch_cleanup;
                }
            }

            sr = dispatch_request(conn, &url, method, data, data_len,
                                   upload_file, upload_size, chunked_upload,
                                   &hdrs, use_proxy, opts, out, &ttfb_start);

            if (sr != 0 && !retried_this_hop && reuse_connection && is_connection_error(conn)) {
                retried_this_hop = true;
                need_fresh_connection = true;
                free_built_headers(&hdrs);
                continue;
            }

        dispatch_cleanup:
            free_built_headers(&hdrs);
            if (sr != 0) goto error_cleanup;
            break; /* hop succeeded */
        }

        if (opts->cookie_jar != NULL && out->resp.set_cookie_len > 0) {
            char *buf = out->resp.set_cookie_buf;
            /* cppcheck-suppress constVariablePointer */
            char *line = buf;
            while (*line != '\0') {
                char *nl = strchr(line, '\n');
                if (nl != NULL) *nl = '\0';
                cookie_jar_add_set_cookie(opts->cookie_jar, line, url.host, url.path);
                if (nl == NULL) break;
                line = nl + 1;
            }
        }

        if (opts->fail_on_http_error && out->resp.status_code >= 400) {
            snprintf(out->error, sizeof(out->error), "HTTP %d", out->resp.status_code);
            goto error_cleanup;
        }
        out->ttfb_ms = out->resp.ttfb_ms;

        update_hop_record(&out->hops[out->hop_count], &url, out, reuse_connection,
                          hop_dns_ms, hop_connect_ms, &race_info);

        struct redirect_plan rplan;
        bool can_redirect = false;
        if (plan_redirect(&out->resp, &url, &rplan)) {
            snprintf(out->hops[out->hop_count].redirect_to_host,
                     sizeof(out->hops[out->hop_count].redirect_to_host),
                     "%s", rplan.redirected_url.host);
            snprintf(out->hops[out->hop_count].redirect_url,
                     sizeof(out->hops[out->hop_count].redirect_url),
                     "%s", rplan.next_url);
            out->hops[out->hop_count].has_redirect_target = true;
            can_redirect = true;
            if (rplan.downgrade_to_get) {
                safe_strlcpy(method, "GET", sizeof(method));
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
            snprintf(out->error, sizeof(out->error),
                     "Too many redirects (limit %d)", opts->max_redirects);
            goto error_cleanup;
        }

        bool same_host = (strcmp(rplan.redirected_url.host, conn_host) == 0 &&
                          strcmp(rplan.redirected_url.port, conn_port) == 0 &&
                          rplan.redirected_url.use_tls == *conn_use_tls);
        if (!same_host) {
            close_connection(conn);
            freeaddrinfo(*conn_addrs);
            *conn_addrs = NULL;
            conn_host[0] = '\0'; conn_port[0] = '\0';
        }

        safe_strlcpy(current_url, rplan.next_url, sizeof(current_url));
        redirect_count++;
    }

error_cleanup:
    rc = -1;
    free(out->hops);
    out->hops = NULL;
    free(out->resp.body_buf);
    out->resp.body_buf = NULL;
    out->resp.body_len = 0;
    out->resp.body_cap = 0;
done:
    close_upload_file(&upload_file);
    clock_gettime(CLOCK_MONOTONIC, &total_end);
    out->total_ms = ms_between(&total_start, &total_end);
    if (rc != 0 || reuse == NULL) {
        close_connection(conn);
        freeaddrinfo(*conn_addrs);
        *conn_addrs = NULL;
        conn_host[0] = '\0';
        conn_port[0] = '\0';
    }

    if (rc != 0 && out->error[0] == '\0')
        snprintf(out->error, sizeof(out->error), "Request failed");
    return rc;
}

void init_run_options(struct run_options *opts, const struct cmdline_opts *c) {
    memset(opts, 0, sizeof(*opts));
    opts->follow_redirects = c->follow_redirects;
    safe_strlcpy(opts->method, c->request_method, sizeof(opts->method));
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
    opts->force_http_version = c->force_http_version;
    opts->compressed = c->compressed;
    opts->unix_socket_path = c->unix_socket_path;
    opts->cacert = c->cacert;
    opts->capath = c->capath;
    opts->tls_params.cacert = c->cacert;
    opts->tls_params.capath = c->capath;
    opts->is_head_method = (strcasecmp(opts->method, "HEAD") == 0);
}

/* --- Single request mode --- */
int run_single_request(const struct cmdline_opts *c, struct run_options *opts,
                               struct run_result *result, FILE *body_out,
                               struct connection_state *reuse) {
    /* Proxy host/port are parsed once in main() and passed in on opts; they
     * are preserved here because init_run_options() zeroes the struct. */
    const char *proxy_host = opts->proxy_host;
    const char *proxy_port = opts->proxy_port;
    struct cookie_jar *cookie_jar = opts->cookie_jar;
    SSL_CTX *existing_tls_ctx = opts->tls_ctx;
    struct dns_cache *existing_dns_cache = opts->dns_cache;
    init_run_options(opts, c);
    opts->tls_ctx = existing_tls_ctx;
    opts->dns_cache = existing_dns_cache;
    opts->body_out = body_out;
    opts->proxy_host = proxy_host;
    opts->proxy_port = proxy_port;
    opts->cookie_jar = cookie_jar;

    if (opts->dns_cache == NULL) {
        opts->dns_cache = dns_cache_create(300000);
        if (opts->dns_cache == NULL) {
            fprintf(stderr, "DNS cache setup failed: out of memory\n"); return -1;
        }
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
