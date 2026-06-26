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

static int run_request(const char *input_url, const struct run_options *opts, struct run_result *out);

static const struct resolve_entry *find_resolve_entry(
    const struct resolve_entry *entries, int count, const char *host, const char *port)
{
    for (int i = 0; i < count; i++) {
        if (strcmp(entries[i].host, host) == 0 && strcmp(entries[i].port, port) == 0)
            return &entries[i];
    }
    return NULL;
}

static struct addrinfo *build_addrinfo_from_resolve(const struct resolve_entry *re) {
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
    task->ok = (run_request(task->url, task->opts, task->result) == 0);
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
        task_a.ok = (run_request(url_a, opts_a, result_a) == 0);

    if (pthread_create(&thread_b, NULL, run_request_thread, &task_b) == 0)
        thread_b_started = true;
    else
        task_b.ok = (run_request(url_b, opts_b, result_b) == 0);

    if (thread_a_started) (void)pthread_join(thread_a, NULL);
    if (thread_b_started) (void)pthread_join(thread_b, NULL);

    *ok_a = task_a.ok;
    *ok_b = task_b.ok;
}

static int run_request(const char *input_url, const struct run_options *opts, struct run_result *out) {
    char current_url[2048], next_url[2048];
    int redirect_count = 0;
    FILE *upload_file = NULL;
    size_t upload_size = 0;
    struct timespec total_start, total_end;
    int preferred_family = AF_INET;
    struct connection conn;
    struct addrinfo *conn_addrs = NULL;
    char conn_host[256] = "", conn_port[16] = "";
    bool conn_use_tls = false;
    int gai_error = 0;

    memset(out, 0, sizeof(*out));
    out->ttfb_ms = -1.0;
    out->error[0] = '\0';
    memset(&conn, 0, sizeof(conn));
    conn.fd = -1;

    if (strlen(input_url) >= sizeof(current_url)) {
        snprintf(out->error, sizeof(out->error), "URL too long"); return -1;
    }
    strcpy(current_url, input_url);

    bool chunked_upload = false;
    if (opts->upload_path != NULL) {
        if (strcmp(opts->upload_path, "-") == 0) {
            upload_file = stdin;
            upload_size = 0;
            chunked_upload = true;
        } else {
            struct stat st;
            upload_file = fopen(opts->upload_path, "rb");
            if (upload_file == NULL) {
                snprintf(out->error, sizeof(out->error), "Unable to open upload file '%s': %s",
                         opts->upload_path, strerror(errno)); return -1;
            }
            if (stat(opts->upload_path, &st) != 0) {
                snprintf(out->error, sizeof(out->error), "Unable to stat upload file '%s': %s",
                         opts->upload_path, strerror(errno));
                close_upload_file(&upload_file); return -1;
            }
            if (st.st_size < 0) {
                snprintf(out->error, sizeof(out->error), "Upload file size is invalid");
                close_upload_file(&upload_file); return -1;
            }
            if ((unsigned long long)st.st_size > (unsigned long long)SIZE_MAX) {
                snprintf(out->error, sizeof(out->error), "Upload file is too large");
                close_upload_file(&upload_file); return -1;
            }
            upload_size = (size_t)st.st_size;
        }
    }

    out->hops = calloc((size_t)opts->max_redirects + 1, sizeof(*out->hops));
    if (out->hops == NULL) die("calloc");

    if (clock_gettime(CLOCK_MONOTONIC, &total_start) != 0) die("clock_gettime");

    char method[8];
    const char *data;
    strcpy(method, opts->method);
    data = opts->data;

    for (;;) {
        struct url_info url, redirected_url;
        struct addrinfo *addrs = NULL;
        struct connect_race_info race_info;
        struct timespec dns_start = {0, 0}, dns_end = {0, 0};
        struct timespec connect_start, connect_end;
        struct timespec ttfb_start;
        bool can_redirect = false, reuse_connection = false;

        if (opts->max_time_ms > 0) {
            long rem = deadline_remaining_ms(&total_start, opts->max_time_ms);
            if (rem <= 0) {
                snprintf(out->error, sizeof(out->error), "Operation timed out after %d ms", opts->max_time_ms);
                free_run_result(out); close_upload_file(&upload_file);
                close_connection(&conn); freeaddrinfo(conn_addrs); return -1;
            }
        }

        if (parse_url(current_url, &url) != 0) {
            snprintf(out->error, sizeof(out->error), "Invalid URL: %s", current_url);
            free_run_result(out); close_upload_file(&upload_file);
            close_connection(&conn); freeaddrinfo(conn_addrs); return -1;
        }
        if (out->hop_count >= opts->max_redirects + 1) {
            snprintf(out->error, sizeof(out->error), "Too many hops");
            free_run_result(out); close_upload_file(&upload_file);
            close_connection(&conn); freeaddrinfo(conn_addrs); return -1;
        }
        memset(&out->hops[out->hop_count], 0, sizeof(out->hops[out->hop_count]));

        bool use_proxy = (opts->proxy_host != NULL);

        if (use_proxy) {
            reuse_connection = false;
            strcpy(out->hops[out->hop_count].connected_ip, "via-proxy");
            out->hops[out->hop_count].connected_family = AF_UNSPEC;
        } else {
            reuse_connection = (conn.fd >= 0 &&
                strcmp(url.host, conn_host) == 0 &&
                strcmp(url.port, conn_port) == 0 &&
                url.use_tls == conn_use_tls);
            if (reuse_connection && out->hop_count > 0) {
                const struct hop_info *prev = &out->hops[out->hop_count - 1];
                strcpy(out->hops[out->hop_count].connected_ip, prev->connected_ip);
                out->hops[out->hop_count].connected_family = prev->connected_family;
            }
        }

        if (!reuse_connection) {
            close_connection(&conn);
            freeaddrinfo(conn_addrs);
            conn_addrs = NULL;
            conn_host[0] = '\0'; conn_port[0] = '\0';

            bool use_unix = (opts->unix_socket_path != NULL);
            if (!use_unix) {
                const struct resolve_entry *re = find_resolve_entry(opts->resolve_entries, opts->resolve_count, url.host, url.port);
                if (re != NULL) {
                    addrs = build_addrinfo_from_resolve(re);
                    gai_error = (addrs != NULL) ? 0 : EAI_FAIL;
                    clock_gettime(CLOCK_MONOTONIC, &dns_start);
                    dns_end = dns_start;
                } else {
                    clock_gettime(CLOCK_MONOTONIC, &dns_start);
                    addrs = resolve_dns_timeout(&url, opts->address_family, &gai_error, 5000);
                    clock_gettime(CLOCK_MONOTONIC, &dns_end);
                }
                if (addrs == NULL) {
                    snprintf(out->error, sizeof(out->error), "DNS resolution failed: %s", gai_strerror(gai_error));
                    free_run_result(out); close_upload_file(&upload_file); return -1;
                }
                out->dns_ms += ms_between(&dns_start, &dns_end);
            }
            conn_addrs = addrs;
            strcpy(conn_host, url.host);
            strcpy(conn_port, url.port);
            conn_use_tls = url.use_tls;

            clock_gettime(CLOCK_MONOTONIC, &connect_start);
            int effective_connect_ms = opts->connect_timeout_ms;
            if (opts->max_time_ms > 0) {
                long rem = deadline_remaining_ms(&total_start, opts->max_time_ms);
                if (rem <= 0) {
                    snprintf(out->error, sizeof(out->error), "Operation timed out after %d ms", opts->max_time_ms);
                    freeaddrinfo(addrs); conn_addrs = NULL;
                    free_run_result(out); close_upload_file(&upload_file); return -1;
                }
                if (effective_connect_ms <= 0 || (int)rem < effective_connect_ms)
                    effective_connect_ms = (int)rem;
            }

            int fd;
            if (opts->unix_socket_path != NULL) {
                clock_gettime(CLOCK_MONOTONIC, &connect_start);
                fd = connect_unix_socket(opts->unix_socket_path, out->error, sizeof(out->error));
                clock_gettime(CLOCK_MONOTONIC, &connect_end);
                if (fd < 0) {
                    free_run_result(out); close_upload_file(&upload_file); return -1;
                }
                snprintf(out->hops[out->hop_count].connected_ip,
                         sizeof(out->hops[out->hop_count].connected_ip),
                         "%s", opts->unix_socket_path);
                out->hops[out->hop_count].connected_family = AF_UNIX;
                out->connect_ms += ms_between(&connect_start, &connect_end);
                conn.fd = fd;
                conn.use_tls = url.use_tls;
                conn.ctx = NULL; conn.ssl = NULL;
                conn.verbose = opts->verbose;
            } else if (use_proxy) {
                struct url_info proxy_ui;
                memset(&proxy_ui, 0, sizeof(proxy_ui));
                strncpy(proxy_ui.host, opts->proxy_host, sizeof(proxy_ui.host) - 1);
                if (opts->proxy_port != NULL)
                    strncpy(proxy_ui.port, opts->proxy_port, sizeof(proxy_ui.port) - 1);
                else
                    strcpy(proxy_ui.port, "8080");
                freeaddrinfo(addrs); conn_addrs = NULL;
                addrs = resolve_dns_timeout(&proxy_ui, opts->address_family, &gai_error, 5000);
                if (addrs == NULL) {
                    snprintf(out->error, sizeof(out->error), "Proxy DNS resolution failed: %s", gai_strerror(gai_error));
                    free_run_result(out); close_upload_file(&upload_file); return -1;
                }
                conn_addrs = addrs;
                strcpy(conn_host, proxy_ui.host);
                strcpy(conn_port, proxy_ui.port);
                conn_use_tls = false;

                fd = connect_tcp(addrs,
                    out->hops[out->hop_count].connected_ip,
                    sizeof(out->hops[out->hop_count].connected_ip),
                    &out->hops[out->hop_count].connected_family,
                    effective_connect_ms, &race_info,
                    opts->happy_eyeballs, preferred_family,
                    opts->bind_interface);
                clock_gettime(CLOCK_MONOTONIC, &connect_end);
                if (fd < 0) {
                    snprintf(out->error, sizeof(out->error), "Proxy TCP connect failed: %s", strerror(errno));
                    freeaddrinfo(addrs); conn_addrs = NULL;
                    free_run_result(out); close_upload_file(&upload_file); return -1;
                }
                preferred_family = out->hops[out->hop_count].connected_family;
                out->connect_ms += (race_info.winner_connect_ms > 0.0) ? race_info.winner_connect_ms
                                    : ms_between(&connect_start, &connect_end);
                conn.fd = fd;
                { int one = 1; (void)setsockopt(conn.fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)); }
                conn.use_tls = false;
                conn.ctx = NULL; conn.ssl = NULL;
                conn.verbose = opts->verbose;

                if (url.use_tls) {
                    int proxy_rc = proxy_connect(&conn, proxy_ui.host, proxy_ui.port, &url,
                                                  effective_connect_ms, out->error, sizeof(out->error));
                    if (proxy_rc != 0) {
                        close_connection(&conn); freeaddrinfo(addrs); conn_addrs = NULL;
                        free_run_result(out); close_upload_file(&upload_file); return -1;
                    }
                    if (init_tls(&conn, url.host, opts->insecure_tls,
                                 opts->tls_min_version, opts->tls_max_version,
                                 out->error, sizeof(out->error)) != 0) {
                        close_connection(&conn); freeaddrinfo(addrs); conn_addrs = NULL;
                        free_run_result(out); close_upload_file(&upload_file); return -1;
                    }
                }
            } else {
                fd = connect_tcp(addrs,
                    out->hops[out->hop_count].connected_ip,
                    sizeof(out->hops[out->hop_count].connected_ip),
                    &out->hops[out->hop_count].connected_family,
                    effective_connect_ms, &race_info,
                    opts->happy_eyeballs, preferred_family,
                    opts->bind_interface);
                clock_gettime(CLOCK_MONOTONIC, &connect_end);
                if (fd < 0) {
                    snprintf(out->error, sizeof(out->error), "TCP connect failed: %s", strerror(errno));
                    freeaddrinfo(addrs); conn_addrs = NULL;
                    free_run_result(out); close_upload_file(&upload_file); return -1;
                }
                preferred_family = out->hops[out->hop_count].connected_family;
                out->connect_ms += (race_info.winner_connect_ms > 0.0) ? race_info.winner_connect_ms
                                    : ms_between(&connect_start, &connect_end);
                conn.fd = fd;
                { int one = 1; (void)setsockopt(conn.fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)); }
                conn.use_tls = url.use_tls;
                conn.ctx = NULL; conn.ssl = NULL;
                conn.verbose = opts->verbose;
            }

            int effective_read_ms = opts->read_timeout_ms;
            if (effective_read_ms <= 0) effective_read_ms = 30000;
            if (opts->max_time_ms > 0) {
                long rem = deadline_remaining_ms(&total_start, opts->max_time_ms);
                if (rem <= 0) {
                    snprintf(out->error, sizeof(out->error), "Operation timed out after %d ms", opts->max_time_ms);
                    close_connection(&conn); freeaddrinfo(addrs); conn_addrs = NULL;
                    free_run_result(out); close_upload_file(&upload_file); return -1;
                }
                if (effective_read_ms <= 0 || (int)rem < effective_read_ms)
                    effective_read_ms = (int)rem;
            }
            apply_socket_timeout(conn.fd, effective_read_ms);

            if (!use_proxy && url.use_tls) {
                if (init_tls(&conn, url.host, opts->insecure_tls,
                             opts->tls_min_version, opts->tls_max_version,
                             out->error, sizeof(out->error)) != 0) {
                    close_connection(&conn); freeaddrinfo(addrs); conn_addrs = NULL;
                    free_run_result(out); close_upload_file(&upload_file); return -1;
                }
            }
        } else {
            addrs = conn_addrs;
            memset(&race_info, 0, sizeof(race_info));
        }

        clock_gettime(CLOCK_MONOTONIC, &ttfb_start);
        if (upload_file != NULL && !chunked_upload) {
            if (fseeko(upload_file, 0, SEEK_SET) != 0) {
                snprintf(out->error, sizeof(out->error), "Failed to rewind upload file");
                close_connection(&conn); freeaddrinfo(conn_addrs); conn_addrs = NULL;
                free_run_result(out); close_upload_file(&upload_file); return -1;
            }
        }

        char cookie_header_buf[8192] = "";
        const char *cookie_header_str = NULL;

        if (opts->cookie_jar != NULL) {
            cookie_jar_get_header(opts->cookie_jar, url.host, url.path,
                                  cookie_header_buf, sizeof(cookie_header_buf));
            if (cookie_header_buf[0] != '\0') cookie_header_str = cookie_header_buf;
        }

        char referer_header_buf[2048] = "";
        if (opts->referer != NULL) {
            bool has_referer = false;
            for (size_t i = 0; i < opts->extra_header_count; i++) {
                if (opts->extra_headers[i] != NULL &&
                    strncasecmp(opts->extra_headers[i], "Referer:", 8) == 0) {
                    has_referer = true; break;
                }
            }
            if (!has_referer) {
                int n = snprintf(referer_header_buf, sizeof(referer_header_buf), "Referer: %s", opts->referer);
                if (n < 0 || (size_t)n >= sizeof(referer_header_buf)) referer_header_buf[0] = '\0';
            }
        }

        const char **send_headers = opts->extra_headers;
        size_t send_header_count = opts->extra_header_count;
        const char *stack_headers[32];

        if (cookie_header_str != NULL) {
            bool has_cookie = false;
            for (size_t i = 0; i < opts->extra_header_count; i++) {
                if (opts->extra_headers[i] != NULL &&
                    strncasecmp(opts->extra_headers[i], "Cookie:", 7) == 0) {
                    has_cookie = true; break;
                }
            }
            if (!has_cookie) {
                size_t total = opts->extra_header_count + (referer_header_buf[0] != '\0' ? 2 : 1);
                if (total <= sizeof(stack_headers) / sizeof(stack_headers[0])) {
                    for (size_t i = 0; i < opts->extra_header_count; i++)
                        stack_headers[i] = opts->extra_headers[i];
                    stack_headers[opts->extra_header_count] = cookie_header_str;
                    if (referer_header_buf[0] != '\0')
                        stack_headers[opts->extra_header_count + 1] = referer_header_buf;
                    send_headers = stack_headers;
                } else {
                    const char **dh = malloc(total * sizeof(*dh));
                    if (dh != NULL) {
                        for (size_t i = 0; i < opts->extra_header_count; i++)
                            dh[i] = opts->extra_headers[i];
                        dh[opts->extra_header_count] = cookie_header_str;
                        if (referer_header_buf[0] != '\0')
                            dh[opts->extra_header_count + 1] = referer_header_buf;
                        send_headers = dh;
                    }
                }
                send_header_count = total;
            }
        }

        if (send_headers == opts->extra_headers && referer_header_buf[0] != '\0') {
            size_t total = opts->extra_header_count + 1;
            if (total <= sizeof(stack_headers) / sizeof(stack_headers[0])) {
                for (size_t i = 0; i < opts->extra_header_count; i++)
                    stack_headers[i] = opts->extra_headers[i];
                stack_headers[opts->extra_header_count] = referer_header_buf;
                send_headers = stack_headers;
                send_header_count = total;
            } else {
                const char **dh = malloc(total * sizeof(*dh));
                if (dh != NULL) {
                    for (size_t i = 0; i < opts->extra_header_count; i++)
                        dh[i] = opts->extra_headers[i];
                    dh[opts->extra_header_count] = referer_header_buf;
                    send_headers = dh;
                    send_header_count = total;
                }
            }
        }

        int sr = send_request(&conn, &url, method, data,
                upload_file, upload_size, send_headers, send_header_count,
                opts->basic_auth, opts->user_agent, out->error, sizeof(out->error),
                use_proxy && !url.use_tls, chunked_upload, opts->compressed);
        if (send_headers != opts->extra_headers && send_headers != stack_headers)
            free((void *)send_headers);

        if (sr != 0) {
            close_connection(&conn); freeaddrinfo(conn_addrs); conn_addrs = NULL;
            free_run_result(out); close_upload_file(&upload_file); return -1;
        }

        bool head_method = (strcasecmp(opts->method, "HEAD") == 0);
        if (receive_response(&conn, &ttfb_start, &out->resp, out->error, sizeof(out->error),
                opts->body_out, opts->follow_redirects, opts->fail_on_http_error, head_method) != 0) {
            close_connection(&conn); freeaddrinfo(conn_addrs); conn_addrs = NULL;
            free_run_result(out); close_upload_file(&upload_file); return -1;
        }

        if (opts->cookie_jar != NULL && out->resp.set_cookie_len > 0) {
            char *buf = out->resp.set_cookie_buf;
            char *line = buf;
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
            close_connection(&conn); freeaddrinfo(conn_addrs); conn_addrs = NULL;
            free_run_result(out); close_upload_file(&upload_file); return -1;
        }
        out->ttfb_ms = out->resp.ttfb_ms;

        snprintf(out->hops[out->hop_count].host, sizeof(out->hops[out->hop_count].host), "%s", url.host);
        out->hops[out->hop_count].status_code = out->resp.status_code;
        if (!reuse_connection) {
            out->hops[out->hop_count].dns_ms = ms_between(&dns_start, &dns_end);
            out->hops[out->hop_count].tcp_ms = (race_info.winner_connect_ms > 0.0) ? race_info.winner_connect_ms
                                                : ms_between(&connect_start, &connect_end);
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
            if (out->resp.status_code == 303) {
                strcpy(method, "GET");
                data = NULL;
                close_upload_file(&upload_file);
                upload_size = 0;
                chunked_upload = false;
            }
        }

        out->hop_count++;

        if (!opts->follow_redirects || !can_redirect) {
            if (format_url(&url, out->final_url, sizeof(out->final_url)) != 0)
                snprintf(out->final_url, sizeof(out->final_url), "%s", current_url);
            close_connection(&conn); freeaddrinfo(conn_addrs); conn_addrs = NULL;
            break;
        }

        if (redirect_count >= opts->max_redirects) {
            snprintf(out->error, sizeof(out->error), "Too many redirects (limit %d)", opts->max_redirects);
            free_run_result(out); close_upload_file(&upload_file);
            close_connection(&conn); freeaddrinfo(conn_addrs); return -1;
        }

        bool same_host = (strcmp(redirected_url.host, conn_host) == 0 &&
                          strcmp(redirected_url.port, conn_port) == 0 &&
                          redirected_url.use_tls == conn_use_tls);
        if (!same_host) {
            close_connection(&conn); freeaddrinfo(conn_addrs); conn_addrs = NULL;
            conn_host[0] = '\0'; conn_port[0] = '\0';
        }

        strcpy(current_url, next_url);
        redirect_count++;
    }

    clock_gettime(CLOCK_MONOTONIC, &total_end);
    out->total_ms = ms_between(&total_start, &total_end);
    close_upload_file(&upload_file);
    return 0;
}

void init_run_options(struct run_options *opts, const struct cmdline_opts *c) {
    memset(opts, 0, sizeof(*opts));
    opts->follow_redirects = c->follow_redirects;
    strcpy(opts->method, c->request_method);
    opts->data = c->request_data;
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
}

/* --- Single request mode --- */
int run_single_request(const struct cmdline_opts *c, struct run_options *opts,
                               struct run_result *result, FILE *body_out) {
    init_run_options(opts, c);
    opts->body_out = body_out;
    opts->proxy_host = NULL;
    opts->proxy_port = NULL;
    opts->cookie_jar = NULL;

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
        rc = run_request(c->input_url, opts, result);
        if (rc == 0) break;
        if (attempt + 1 < max_attempts && opts->retry_delay_ms > 0)
            (void)poll(NULL, 0, opts->retry_delay_ms);
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
