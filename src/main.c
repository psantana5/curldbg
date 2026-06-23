#include "curldbg.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>

struct run_options {
    char method[8];
    const char *data;
    bool follow_redirects;
    int address_family;
    int connect_timeout_ms;
    int read_timeout_ms;
    int max_time_ms;
    int max_redirects;
    bool fail_on_http_error;
    FILE *body_out;
    bool insecure_tls;
    const char *basic_auth;
    const char **extra_headers;
    size_t extra_header_count;
    const char *upload_path;
    bool happy_eyeballs;
    bool verbose;
    const char *user_agent;
    const char *proxy_host;
    const char *proxy_port;
    const char *cookie_data;
    const char *cookie_jar_path;
    struct cookie_jar *cookie_jar;
    const struct resolve_entry *resolve_entries;
    int resolve_count;
    const char *referer;
    const char *bind_interface;
    int tls_min_version;
    int tls_max_version;
    int retry_count;
    int retry_delay_ms;
    bool compressed;
    const char *unix_socket_path;
};

struct run_result {
    struct hop_info *hops;
    int hop_count;
    struct response_info resp;
    double dns_ms;
    double connect_ms;
    double ttfb_ms;
    double total_ms;
    char final_url[2048];
    char error[256];
};

struct run_request_task {
    const char *url;
    const struct run_options *opts;
    struct run_result *result;
    bool ok;
};

struct cmdline_opts {
    const char *input_url;
    const char *compare_url;
    char request_method[8];
    bool method_explicit;
    const char *request_data;
    char *request_data_alloc;
    char *request_data_urlencode_alloc;
    bool compare_family_mode;
    bool compare_urls_mode;
    bool follow_redirects;
    bool fail_on_http_error;
    bool silent;
    bool show_error;
    const char *output_path;
    bool output_remote_name;
    bool insecure_tls;
    const char *basic_auth;
    const char *upload_path;
    const char **extra_headers;
    size_t extra_header_count;
    bool wizard_mode;
    bool debug_chaos;
    bool lore_mode;
    bool fika_mode;
    bool happy_eyeballs;
    bool verbose;
    const char *user_agent;
    const char *cookie_data;
    char *cookie_data_alloc;
    char *cookie_header_alloc;
    const char *cookie_jar_path;
    const char *cookie_file_to_load;
    const char *proxy_url;
    int address_family;
    int connect_timeout_ms;
    int read_timeout_ms;
    int max_time_ms;
    int max_redirects;
    struct resolve_entry resolve_entries[MAX_RESOLVE_ENTRIES];
    int resolve_count;
    const char *referer;
    const char *bind_interface;
    int tls_min_version;
    int tls_max_version;
    int retry_count;
    int retry_delay_ms;
    bool compressed;
    const char *unix_socket_path;
    const char *write_out_format;
    const char *cacert;
    const char *capath;
    const char **urls;
    int url_count;
};

static int run_request(const char *input_url, const struct run_options *opts, struct run_result *out);
static void *run_request_thread(void *arg);
static void run_two_requests_parallel(const char *url_a, const struct run_options *opts_a,
                                       struct run_result *result_a, bool *ok_a,
                                       const char *url_b, const struct run_options *opts_b,
                                       struct run_result *result_b, bool *ok_b);
static int output_filename_from_url(const char *input_url, char *out, size_t out_size);

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

static int parse_non_negative_int(const char *value, const char *flag_name) {
    char *end = NULL;
    long parsed;
    if (value == NULL || *value == '\0') {
        fprintf(stderr, "Missing value for %s\n", flag_name); exit(EXIT_FAILURE);
    }
    parsed = strtol(value, &end, 10);
    if (*end != '\0' || parsed < 0 || parsed > 3600000) {
        fprintf(stderr, "Invalid value for %s: %s\n", flag_name, value); exit(EXIT_FAILURE);
    }
    return (int)parsed;
}

static void close_upload_file(FILE **file) {
    if (file != NULL && *file != NULL) { fclose(*file); *file = NULL; }
}

static bool is_loopback_ip(const char *ip) {
    return ip != NULL && (strcmp(ip, "127.0.0.1") == 0 || strcmp(ip, "::1") == 0);
}

static bool is_localhost_url(const char *input_url) {
    struct url_info url;
    if (input_url == NULL) return false;
    if (parse_url(input_url, &url) != 0) return false;
    return strcmp(url.host, "localhost") == 0 ||
           strcmp(url.host, "127.0.0.1") == 0 ||
           strcmp(url.host, "::1") == 0;
}

static void configure_output_buffering(void) {
    if (isatty(fileno(stdout))) { (void)setvbuf(stdout, NULL, _IOLBF, 0); return; }
    (void)setvbuf(stdout, NULL, _IOFBF, 64 * 1024);
}

static void maybe_print_april_fools(void) {
    static bool printed = false;
    time_t now = time(NULL);
    if (now == (time_t)-1 || printed) return;
    struct tm local_tm;
    if (localtime_r(&now, &local_tm) == NULL) return;
    if (local_tm.tm_mon == 3 && local_tm.tm_mday == 1) {
        printf("HTTP/3 disabled due to mercury retrograde\n");
        printed = true;
    }
}

static void print_wizard_banner(void) {
    printf("You are now entering advanced networking wizard mode.\n");
    printf("Latency is temporary. Packets are eternal.\n");
    printf("OH NOW WE'RE TALKING \xf0\x9f\x98\xad\xf0\x9f\x92\x80\n");
}

static void print_fika_banner(void) {
    printf("Pausing requests for mandatory Swedish coffee break...\n");
}

static int output_filename_from_url(const char *input_url, char *out, size_t out_size) {
    struct url_info url;
    if (parse_url(input_url, &url) != 0) return -1;
    const char *path = url.path;
    const char *slash = strrchr(path, '/');
    const char *segment = (slash != NULL) ? slash + 1 : path;
    if (segment[0] == '\0')
        return (snprintf(out, out_size, "index.html") < 0 || (size_t)snprintf(out, out_size, "index.html") >= out_size) ? -1 : 0;
    char name_buf[1024];
    snprintf(name_buf, sizeof(name_buf), "%s", segment);
    char *cut = strpbrk(name_buf, "?#");
    if (cut != NULL) *cut = '\0';
    int n;
    if (name_buf[0] == '\0')
        n = snprintf(out, out_size, "index.html");
    else
        n = snprintf(out, out_size, "%s", name_buf);
    return (n < 0 || (size_t)n >= out_size) ? -1 : 0;
}

static void free_run_result(struct run_result *result) {
    free(result->hops);
    result->hops = NULL;
    result->hop_count = 0;
}

static int final_status_code(const struct run_result *result) {
    return (result->hop_count <= 0) ? 0 : result->hops[result->hop_count - 1].status_code;
}

static void final_endpoint(const struct run_result *result, char *out, size_t out_size) {
    if (result->hop_count <= 0) { snprintf(out, out_size, "n/a"); return; }
    const struct hop_info *hop = &result->hops[result->hop_count - 1];
    snprintf(out, out_size, "%s (%s)", hop->connected_ip, family_name(hop->connected_family));
}

static const char *family_short_name(int family) {
    if (family == AF_INET) return "v4";
    if (family == AF_INET6) return "v6";
    return "?";
}

static void *run_request_thread(void *arg) {
    struct run_request_task *task = (struct run_request_task *)arg;
    task->ok = (run_request(task->url, task->opts, task->result) == 0);
    return NULL;
}

static void run_two_requests_parallel(const char *url_a, const struct run_options *opts_a,
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

static void print_single_output(const struct run_result *result) {
    char endpoint[NI_MAXHOST + 16];
    const struct hop_info *final_hop = NULL;
    int status_code = final_status_code(result);
    final_endpoint(result, endpoint, sizeof(endpoint));
    if (result->hop_count > 0) final_hop = &result->hops[result->hop_count - 1];

    printf("DNS lookup:        %.2f ms\n", result->dns_ms);
    printf("TCP connect:       %.2f ms\n", result->connect_ms);
    if (result->ttfb_ms >= 0.0)
        printf("TTFB:              %.2f ms\n", result->ttfb_ms);
    else
        printf("TTFB:              n/a (no response bytes)\n");
    printf("Total:             %.2f ms\n", result->total_ms);
    if (status_code > 0) printf("HTTP status:       %d\n", status_code);
    printf("Endpoint:          %s\n", endpoint);
    if (final_hop != NULL && is_loopback_ip(final_hop->connected_ip))
        printf("Congratulations, you found yourself.\n");
    if (status_code == 418)
        printf("The server acknowledges your coffee infrastructure.\n");
    if (result->ttfb_ms >= 0.0 && result->ttfb_ms < 5.0)
        printf("WARNING: request arrived before it was sent\n");
    if (result->dns_ms >= 2000.0)
        printf("DNS resolver currently communicating through astral plane\n");
    if (final_hop != NULL && final_hop->has_loser && final_hop->loser_connect_ms >= 0.0)
        printf("Other:             %s (%s, %+0.2f ms)\n",
               final_hop->loser_ip, family_short_name(final_hop->loser_family),
               final_hop->loser_connect_ms - final_hop->tcp_ms);
    printf("Final URL:         %s\n", result->final_url);

    printf("\nRedirect chain:\n");
    for (int i = 0; i < result->hop_count; i++) {
        if (result->hops[i].has_redirect_target)
            printf("[%d] %s -> %s\n", result->hops[i].status_code,
                   result->hops[i].host, result->hops[i].redirect_to_host);
        else
            printf("[%d] %s\n", result->hops[i].status_code, result->hops[i].host);
    }
    if (result->hop_count > 7)
        printf("Redirect chain resembles enterprise architecture.\n");

    printf("\nPer-hop timing:\n");
    for (int i = 0; i < result->hop_count; i++) {
        printf("Hop %d:\n", i + 1);
        printf("  DNS: %.2f ms\n", result->hops[i].dns_ms);
        printf("  TCP: %.2f ms\n", result->hops[i].tcp_ms);
        if (result->hops[i].ttfb_ms >= 0.0)
            printf("  TTFB: %.2f ms\n", result->hops[i].ttfb_ms);
        else
            printf("  TTFB: n/a\n");
        printf("  Connected to: %s (%s)\n",
               result->hops[i].connected_ip, family_name(result->hops[i].connected_family));
        if (result->hops[i].has_loser && result->hops[i].loser_connect_ms >= 0.0)
            printf("  Other: %s (%s, %+0.2f ms)\n",
                   result->hops[i].loser_ip, family_short_name(result->hops[i].loser_family),
                   result->hops[i].loser_connect_ms - result->hops[i].tcp_ms);
    }

    fprintf(stderr, "\nResponse body preview (first ~1KB):\n");
    if (result->resp.preview_len > 0) {
        fwrite(result->resp.preview, 1, result->resp.preview_len, stderr);
        if (result->resp.preview[result->resp.preview_len - 1] != '\n')
            fputc('\n', stderr);
    } else {
        fprintf(stderr, "(empty)\n");
    }
}

static void print_compare_metric_row(const char *metric, double a, double b) {
    char a_buf[48], b_buf[48], delta_buf[64];
    snprintf(a_buf, sizeof(a_buf), (a >= 0.0) ? "%.2f ms" : "n/a", a);
    snprintf(b_buf, sizeof(b_buf), (b >= 0.0) ? "%.2f ms" : "n/a", b);
    if (a >= 0.0 && b >= 0.0) {
        double delta = b - a;
        if (a > 0.0)
            snprintf(delta_buf, sizeof(delta_buf), "%+.2f ms (%+.1f%%)", delta, (delta / a) * 100.0);
        else
            snprintf(delta_buf, sizeof(delta_buf), "%+.2f ms", delta);
    } else {
        snprintf(delta_buf, sizeof(delta_buf), "n/a");
    }
    printf("%-10s | %-24s | %-24s | %-20s\n", metric, a_buf, b_buf, delta_buf);
}

static void print_compare_text_row(const char *metric, const char *a, const char *b) {
    printf("%-10s | %-24s | %-24s | %-20s\n", metric, a, b, (strcmp(a, b) == 0) ? "same" : "different");
}

static void print_compare_family_metric(const char *label, double v4, double v6) {
    double delta = v6 - v4;
    if (v4 < 0.0 || v6 < 0.0) { printf("  %-14s n/a\n", label); return; }
    if (v4 > 0.0)
        printf("  %-14s %+8.2f ms (%+.1f%%)\n", label, delta, (delta / v4) * 100.0);
    else
        printf("  %-14s %+8.2f ms\n", label, delta);
}

static void print_compare_family_run(const char *name, const struct run_result *result, bool ok) {
    printf("%s:\n", name);
    if (!ok) {
        if (result->error[0] != '\0') printf("  error: %s\n", result->error);
        printf("  status: failed\n"); return;
    }
    printf("  status: %d\n", final_status_code(result));
    printf("  total: %.2f ms\n", result->total_ms);
    printf("  dns: %.2f ms\n", result->dns_ms);
    printf("  tcp: %.2f ms\n", result->connect_ms);
    if (result->ttfb_ms >= 0.0) printf("  ttfb: %.2f ms\n", result->ttfb_ms);
    else printf("  ttfb: n/a\n");
    if (result->hop_count > 0) {
        const struct hop_info *last = &result->hops[result->hop_count - 1];
        printf("  connected: %s (%s)\n", last->connected_ip, family_name(last->connected_family));
    } else {
        printf("  connected: n/a\n");
    }
    printf("  final url: %s\n", result->final_url);
}

/* --- Option parsing --- */
static void parse_cmdline(int argc, char **argv, struct cmdline_opts *c) {
    memset(c, 0, sizeof(*c));
    c->happy_eyeballs = true;
    c->max_redirects = DEFAULT_MAX_REDIRECTS;
    c->address_family = AF_UNSPEC;
    strcpy(c->request_method, "GET");

    signal(SIGPIPE, SIG_IGN);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--compare") == 0) { c->compare_family_mode = true; continue; }
        if (strcmp(argv[i], "--compare-urls") == 0) { c->compare_urls_mode = true; continue; }
        if (strcmp(argv[i], "--version") == 0) {
            printf("curldbg %s\n", CURLDBG_VERSION);
            printf("Author: Pau Santana\n"); exit(EXIT_SUCCESS);
        }
        if (strcmp(argv[i], "--wizard") == 0) { c->wizard_mode = true; continue; }
        if (strcmp(argv[i], "--debug-chaos") == 0) { c->debug_chaos = true; continue; }
        if (strcmp(argv[i], "--lore") == 0) { c->lore_mode = true; continue; }
        if (strcmp(argv[i], "--fika") == 0) { c->fika_mode = true; continue; }
        if (strcmp(argv[i], "--no-happy-eyeballs") == 0) { c->happy_eyeballs = false; continue; }
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) { c->verbose = true; continue; }
        if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--insecure") == 0) { c->insecure_tls = true; continue; }
        if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--user") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for %s\n", argv[i]); exit(EXIT_FAILURE); }
            c->basic_auth = argv[++i]; continue;
        }
        if (strcmp(argv[i], "-A") == 0 || strcmp(argv[i], "--user-agent") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for %s\n", argv[i]); exit(EXIT_FAILURE); }
            c->user_agent = argv[++i]; continue;
        }
        if (strcmp(argv[i], "-H") == 0 || strcmp(argv[i], "--header") == 0) {
            const char *header_value;
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for %s\n", argv[i]); exit(EXIT_FAILURE); }
            header_value = argv[++i];
            if (strchr(header_value, '\r') != NULL || strchr(header_value, '\n') != NULL) {
                fprintf(stderr, "Invalid header value (newline detected)\n"); exit(EXIT_FAILURE);
            }
            const char **next = realloc(c->extra_headers, (c->extra_header_count + 1) * sizeof(*c->extra_headers));
            if (next == NULL) { fprintf(stderr, "Out of memory\n"); exit(EXIT_FAILURE); }
            c->extra_headers = next;
            c->extra_headers[c->extra_header_count++] = header_value;
            continue;
        }
        if (strcmp(argv[i], "-T") == 0 || strcmp(argv[i], "--upload-file") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for %s\n", argv[i]); exit(EXIT_FAILURE); }
            if (c->upload_path != NULL) { fprintf(stderr, "Only one upload file is supported\n"); exit(EXIT_FAILURE); }
            c->upload_path = argv[++i]; continue;
        }
        if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--fail") == 0) { c->fail_on_http_error = true; continue; }
        if (strcmp(argv[i], "--progress-bar") == 0) { continue; }
        if (strcmp(argv[i], "-I") == 0 || strcmp(argv[i], "--head") == 0) {
            strcpy(c->request_method, "HEAD"); c->method_explicit = true; continue;
        }
        if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--silent") == 0) { c->silent = true; continue; }
        if (strcmp(argv[i], "-S") == 0 || strcmp(argv[i], "--show-error") == 0) { c->show_error = true; continue; }
        if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for %s\n", argv[i]); exit(EXIT_FAILURE); }
            c->output_path = argv[++i]; continue;
        }
        if (strcmp(argv[i], "-O") == 0 || strcmp(argv[i], "--remote-name") == 0) { c->output_remote_name = true; continue; }
        if (strcmp(argv[i], "-X") == 0 || strcmp(argv[i], "--request") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for %s\n", argv[i]); exit(EXIT_FAILURE); }
            i++;
            if (strcasecmp(argv[i], "GET") == 0) strcpy(c->request_method, "GET");
            else if (strcasecmp(argv[i], "POST") == 0) strcpy(c->request_method, "POST");
            else if (strcasecmp(argv[i], "PUT") == 0) strcpy(c->request_method, "PUT");
            else if (strcasecmp(argv[i], "DELETE") == 0) strcpy(c->request_method, "DELETE");
            else if (strcasecmp(argv[i], "PATCH") == 0) strcpy(c->request_method, "PATCH");
            else if (strcasecmp(argv[i], "OPTIONS") == 0) strcpy(c->request_method, "OPTIONS");
            else {
                size_t mlen = strlen(argv[i]);
                if (mlen < sizeof(c->request_method))
                    memcpy(c->request_method, argv[i], mlen + 1);
                else { fprintf(stderr, "Unknown or unsupported method: %s\n", argv[i]); exit(EXIT_FAILURE); }
            }
            c->method_explicit = true; continue;
        }
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--data") == 0 || strcmp(argv[i], "--data-binary") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for %s\n", argv[i]); free(c->request_data_alloc); exit(EXIT_FAILURE); }
            i++;
            if (argv[i][0] == '@') {
                const char *spec = argv[i] + 1;
                FILE *fp = NULL;
                bool close_fp = false;
                if (spec[0] == '-' && spec[1] == '\0') { fp = stdin; }
                else { fp = fopen(spec, "rb"); if (fp == NULL) { fprintf(stderr, "Unable to open data file '%s': %s\n", spec, strerror(errno)); exit(EXIT_FAILURE); } close_fp = true; }
                size_t cap = 4096, total = 0;
                char *data = malloc(cap);
                if (data == NULL) { fprintf(stderr, "Out of memory reading data\n"); if (close_fp) fclose(fp); exit(EXIT_FAILURE); }
                char buf[4096]; size_t nread;
                while ((nread = fread(buf, 1, sizeof(buf), fp)) > 0) {
                    if (total + nread >= cap) { cap = (cap > SIZE_MAX / 2) ? SIZE_MAX : cap * 2; char *tmp = realloc(data, cap); if (tmp == NULL) { free(data); if (close_fp) fclose(fp); fprintf(stderr, "Out of memory reading data\n"); exit(EXIT_FAILURE); } data = tmp; }
                    memcpy(data + total, buf, nread); total += nread;
                }
                if (ferror(fp)) { free(data); if (close_fp) fclose(fp); fprintf(stderr, "Failed to read data from '%s'\n", spec); exit(EXIT_FAILURE); }
                if (close_fp) fclose(fp);
                data[total] = '\0';
                if (c->request_data != NULL) {
                    char *combined = malloc(strlen(c->request_data) + 1 + total + 1);
                    if (combined == NULL) { free(data); fprintf(stderr, "Out of memory\n"); exit(EXIT_FAILURE); }
                    snprintf(combined, strlen(c->request_data) + 1 + total + 1, "%s&%s", c->request_data, data);
                    free(c->request_data_alloc); free(data);
                    c->request_data = combined; c->request_data_alloc = combined;
                    c->request_data_urlencode_alloc = NULL;
                } else {
                    free(c->request_data_alloc);
                    c->request_data = data; c->request_data_alloc = data;
                    c->request_data_urlencode_alloc = NULL;
                }
            } else {
                if (c->request_data != NULL) {
                    size_t new_len = strlen(c->request_data) + 1 + strlen(argv[i]) + 1;
                    char *combined = malloc(new_len);
                    if (combined == NULL) { fprintf(stderr, "Out of memory\n"); exit(EXIT_FAILURE); }
                    snprintf(combined, new_len, "%s&%s", c->request_data, argv[i]);
                    free(c->request_data_alloc);
                    c->request_data = combined; c->request_data_alloc = combined;
                    c->request_data_urlencode_alloc = NULL;
                } else {
                    c->request_data = argv[i];
                }
            }
            continue;
        }
        if (strcmp(argv[i], "-L") == 0 || strcmp(argv[i], "--location") == 0) { c->follow_redirects = true; continue; }
        if (strcmp(argv[i], "-4") == 0) {
            if (c->address_family == AF_INET6) { fprintf(stderr, "-4 and -6 are mutually exclusive\n"); exit(EXIT_FAILURE); }
            c->address_family = AF_INET; continue;
        }
        if (strcmp(argv[i], "-6") == 0) {
            if (c->address_family == AF_INET) { fprintf(stderr, "-4 and -6 are mutually exclusive\n"); exit(EXIT_FAILURE); }
            c->address_family = AF_INET6; continue;
        }
        if (strcmp(argv[i], "--connect-timeout") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for --connect-timeout\n"); exit(EXIT_FAILURE); }
            c->connect_timeout_ms = parse_non_negative_int(argv[++i], "--connect-timeout"); continue;
        }
        if (strcmp(argv[i], "--read-timeout") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for --read-timeout\n"); exit(EXIT_FAILURE); }
            c->read_timeout_ms = parse_non_negative_int(argv[++i], "--read-timeout"); continue;
        }
        if (strcmp(argv[i], "--max-time") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for --max-time\n"); exit(EXIT_FAILURE); }
            c->max_time_ms = parse_non_negative_int(argv[++i], "--max-time"); continue;
        }
        if (strcmp(argv[i], "--max-redirs") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for --max-redirs\n"); exit(EXIT_FAILURE); }
            c->max_redirects = parse_non_negative_int(argv[++i], "--max-redirs"); continue;
        }
        if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--cookie") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for %s\n", argv[i]); exit(EXIT_FAILURE); }
            i++;
            if (argv[i][0] == '@') { c->cookie_file_to_load = argv[i] + 1; }
            else {
                if (c->cookie_data != NULL) {
                    size_t new_len = strlen(c->cookie_data) + 2 + strlen(argv[i]) + 1;
                    char *combined = malloc(new_len);
                    if (combined == NULL) { fprintf(stderr, "Out of memory\n"); exit(EXIT_FAILURE); }
                    snprintf(combined, new_len, "%s; %s", c->cookie_data, argv[i]);
                    free(c->cookie_data_alloc);
                    c->cookie_data = combined; c->cookie_data_alloc = combined;
                } else {
                    c->cookie_data = argv[i];
                }
            }
            continue;
        }
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--cookie-jar") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for %s\n", argv[i]); exit(EXIT_FAILURE); }
            c->cookie_jar_path = argv[++i]; continue;
        }
        if (strcmp(argv[i], "--proxy") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for --proxy\n"); exit(EXIT_FAILURE); }
            c->proxy_url = argv[++i];
            if (strncmp(c->proxy_url, "http://", 7) != 0 && strncmp(c->proxy_url, "https://", 8) != 0) {
                fprintf(stderr, "--proxy only supports http:// URLs\n"); exit(EXIT_FAILURE);
            }
            if (strncmp(c->proxy_url, "https://", 8) == 0) {
                fprintf(stderr, "--proxy does not support https:// proxy URLs (only http://)\n"); exit(EXIT_FAILURE);
            }
            continue;
        }
        if (strcmp(argv[i], "--resolve") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for --resolve\n"); exit(EXIT_FAILURE); }
            if (c->resolve_count >= MAX_RESOLVE_ENTRIES) { fprintf(stderr, "Too many --resolve entries (max %d)\n", MAX_RESOLVE_ENTRIES); exit(EXIT_FAILURE); }
            const char *val = argv[++i];
            const char *last_colon = strrchr(val, ':');
            if (last_colon == NULL || last_colon == val) {
                fprintf(stderr, "Invalid --resolve format (expected host:port:address)\n"); exit(EXIT_FAILURE);
            }
            const char *addr = last_colon + 1;
            size_t hostport_len = (size_t)(last_colon - val);
            char hostport[512];
            if (hostport_len >= sizeof(hostport)) { fprintf(stderr, "--resolve host:port too long\n"); exit(EXIT_FAILURE); }
            memcpy(hostport, val, hostport_len);
            hostport[hostport_len] = '\0';
            const char *port_colon = strrchr(hostport, ':');
            if (port_colon == NULL) {
                fprintf(stderr, "Invalid --resolve format (expected host:port:address)\n"); exit(EXIT_FAILURE);
            }
            *((char *)port_colon) = '\0';
            const char *host = hostport;
            const char *port = port_colon + 1;
            struct resolve_entry *re = &c->resolve_entries[c->resolve_count];
            memset(re, 0, sizeof(*re));
            if (strlen(host) >= sizeof(re->host) || strlen(port) >= sizeof(re->port)) {
                fprintf(stderr, "--resolve host or port too long\n"); exit(EXIT_FAILURE);
            }
            strcpy(re->host, host);
            strcpy(re->port, port);
            if (inet_pton(AF_INET, addr, &((struct sockaddr_in *)&re->ss)->sin_addr) == 1) {
                re->family = AF_INET;
                re->ss_len = sizeof(struct sockaddr_in);
                ((struct sockaddr_in *)&re->ss)->sin_family = AF_INET;
            } else if (inet_pton(AF_INET6, addr, &((struct sockaddr_in6 *)&re->ss)->sin6_addr) == 1) {
                re->family = AF_INET6;
                re->ss_len = sizeof(struct sockaddr_in6);
                ((struct sockaddr_in6 *)&re->ss)->sin6_family = AF_INET6;
            } else {
                fprintf(stderr, "Invalid address in --resolve: %s\n", addr); exit(EXIT_FAILURE);
            }
            c->resolve_count++;
            continue;
        }
        if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--referer") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for %s\n", argv[i]); exit(EXIT_FAILURE); }
            c->referer = argv[++i]; continue;
        }
        if (strcmp(argv[i], "--interface") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for --interface\n"); exit(EXIT_FAILURE); }
            c->bind_interface = argv[++i]; continue;
        }
        if (strcmp(argv[i], "--tlsv1.2") == 0) {
            c->tls_min_version = TLS1_2_VERSION;
            c->tls_max_version = TLS1_2_VERSION;
            continue;
        }
        if (strcmp(argv[i], "--tlsv1.3") == 0) {
            c->tls_min_version = TLS1_3_VERSION;
            c->tls_max_version = TLS1_3_VERSION;
            continue;
        }
        if (strcmp(argv[i], "--retry") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for --retry\n"); exit(EXIT_FAILURE); }
            c->retry_count = parse_non_negative_int(argv[++i], "--retry"); continue;
        }
        if (strcmp(argv[i], "--retry-delay") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for --retry-delay\n"); exit(EXIT_FAILURE); }
            c->retry_delay_ms = parse_non_negative_int(argv[++i], "--retry-delay") * 1000; continue;
        }
        if (strcmp(argv[i], "--cacert") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for --cacert\n"); exit(EXIT_FAILURE); }
            c->cacert = argv[++i]; continue;
        }
        if (strcmp(argv[i], "--capath") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for --capath\n"); exit(EXIT_FAILURE); }
            c->capath = argv[++i]; continue;
        }
        if (strcmp(argv[i], "--compressed") == 0) { c->compressed = true; continue; }
        if (strcmp(argv[i], "--data-urlencode") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for --data-urlencode\n"); exit(EXIT_FAILURE); }
            i++;
            const char *arg = argv[i];
            const char *content = NULL;
            const char *name = NULL;
            char *encoded = NULL;
            char *file_buf = NULL;
            /* Determine if we need to URL-encode and handle @file / name@file / name=content */
            if (arg[0] == '@') {
                /* @file */
                const char *fpath = arg + 1;
                FILE *fp = NULL;
                if (fpath[0] == '-' && fpath[1] == '\0') fp = stdin;
                else fp = fopen(fpath, "rb");
                if (fp == NULL) { fprintf(stderr, "Cannot open '%s' for --data-urlencode\n", fpath); exit(EXIT_FAILURE); }
                size_t cap = 4096, total = 0;
                file_buf = malloc(cap);
                if (file_buf == NULL) { fprintf(stderr, "Out of memory\n"); if (fp != stdin) fclose(fp); exit(EXIT_FAILURE); }
                char tmp[4096]; size_t nread;
                while ((nread = fread(tmp, 1, sizeof(tmp), fp)) > 0) {
                    if (total + nread >= cap) { cap = (cap > SIZE_MAX / 2) ? SIZE_MAX : cap * 2; char *t = realloc(file_buf, cap); if (t == NULL) { free(file_buf); if (fp != stdin) fclose(fp); fprintf(stderr, "Out of memory\n"); exit(EXIT_FAILURE); } file_buf = t; }
                    memcpy(file_buf + total, tmp, nread); total += nread;
                }
                if (ferror(fp)) { free(file_buf); if (fp != stdin) fclose(fp); fprintf(stderr, "Failed to read '%s'\n", fpath); exit(EXIT_FAILURE); }
                if (fp != stdin) fclose(fp);
                file_buf[total] = '\0';
                content = file_buf;
            } else if (arg[0] == '=') {
                /* =content */
                content = arg + 1;
            } else {
                /* Check for name@file or name=content */
                const char *at = strchr(arg, '@');
                const char *eq = strchr(arg, '=');
                if (eq != NULL && (at == NULL || eq < at)) {
                    /* name=content */
                    size_t nlen = (size_t)(eq - arg);
                    char *n = malloc(nlen + 1);
                    if (n == NULL) { fprintf(stderr, "Out of memory\n"); exit(EXIT_FAILURE); }
                    memcpy(n, arg, nlen); n[nlen] = '\0';
                    name = n;
                    content = eq + 1;
                } else if (at != NULL) {
                    /* name@file */
                    size_t nlen = (size_t)(at - arg);
                    if (nlen > 0) {
                        char *n = malloc(nlen + 1);
                        if (n == NULL) { fprintf(stderr, "Out of memory\n"); exit(EXIT_FAILURE); }
                        memcpy(n, arg, nlen); n[nlen] = '\0';
                        name = n;
                    }
                    const char *fpath = at + 1;
                    FILE *fp = NULL;
                    if (fpath[0] == '-' && fpath[1] == '\0') fp = stdin;
                    else fp = fopen(fpath, "rb");
                    if (fp == NULL) { fprintf(stderr, "Cannot open '%s' for --data-urlencode\n", fpath); exit(EXIT_FAILURE); }
                    size_t cap = 4096, total = 0;
                    file_buf = malloc(cap);
                    if (file_buf == NULL) { fprintf(stderr, "Out of memory\n"); if (fp != stdin) fclose(fp); exit(EXIT_FAILURE); }
                    char tmp[4096]; size_t nread;
                    while ((nread = fread(tmp, 1, sizeof(tmp), fp)) > 0) {
                        if (total + nread >= cap) { cap = (cap > SIZE_MAX / 2) ? SIZE_MAX : cap * 2; char *t = realloc(file_buf, cap); if (t == NULL) { free(file_buf); if (fp != stdin) fclose(fp); fprintf(stderr, "Out of memory\n"); exit(EXIT_FAILURE); } file_buf = t; }
                        memcpy(file_buf + total, tmp, nread); total += nread;
                    }
                    if (ferror(fp)) { free(file_buf); if (fp != stdin) fclose(fp); fprintf(stderr, "Failed to read '%s'\n", fpath); exit(EXIT_FAILURE); }
                    if (fp != stdin) fclose(fp);
                    file_buf[total] = '\0';
                    content = file_buf;
                } else {
                    /* plain content */
                    content = arg;
                }
            }
            /* URL-encode content */
            size_t clen = strlen(content);
            size_t max_encoded = clen * 3 + 1;
            encoded = malloc(max_encoded);
            if (encoded == NULL) { fprintf(stderr, "Out of memory\n"); free(file_buf); exit(EXIT_FAILURE); }
            if (url_encode(content, encoded, max_encoded) != 0) {
                fprintf(stderr, "URL-encoding failed\n"); free(encoded); free(file_buf); exit(EXIT_FAILURE);
            }
            /* Build final value: [name=]encoded */
            size_t name_len = (name != NULL) ? strlen(name) : 0;
            size_t need = name_len + 1 + strlen(encoded) + 1;
            char *final = malloc(need);
            if (final == NULL) { fprintf(stderr, "Out of memory\n"); free(encoded); free(file_buf); exit(EXIT_FAILURE); }
            if (name != NULL)
                snprintf(final, need, "%s=%s", name, encoded);
            else
                snprintf(final, need, "%s", encoded);
            free(encoded);
            free(file_buf);
            /* Accumulate with existing data */
            if (c->request_data != NULL) {
                size_t new_len = strlen(c->request_data) + 1 + strlen(final) + 1;
                char *combined = malloc(new_len);
                if (combined == NULL) { fprintf(stderr, "Out of memory\n"); free(final); exit(EXIT_FAILURE); }
                snprintf(combined, new_len, "%s&%s", c->request_data, final);
                free(c->request_data_alloc);
                if (c->request_data_urlencode_alloc != NULL && c->request_data_urlencode_alloc != c->request_data_alloc) {
                    free(c->request_data_urlencode_alloc);
                }
                c->request_data = combined;
                c->request_data_alloc = combined;
                c->request_data_urlencode_alloc = NULL;
                free(final);
            } else {
                c->request_data = final;
                c->request_data_alloc = final;
                /* request_data_urlencode_alloc stays NULL, tracked by request_data_alloc */
            }
            if (name != NULL) free((void *)name);
            continue;
        }
        if (strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--write-out") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for %s\n", argv[i]); exit(EXIT_FAILURE); }
            c->write_out_format = argv[++i]; continue;
        }
        if (strcmp(argv[i], "--unix-socket") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for --unix-socket\n"); exit(EXIT_FAILURE); }
            c->unix_socket_path = argv[++i]; continue;
        }

        if (argv[i][0] == '-' && argv[i][1] != '\0' && argv[i][1] != '-' && argv[i][2] != '\0') {
            bool handled = true;
            for (size_t j = 1; argv[i][j] != '\0'; j++) {
                switch (argv[i][j]) {
                    case 'f': c->fail_on_http_error = true; break;
                    case 's': c->silent = true; break;
                    case 'S': c->show_error = true; break;
                    case 'v': c->verbose = true; break;
                    case 'k': c->insecure_tls = true; break;
                    case 'L': c->follow_redirects = true; break;
                    case 'I': strcpy(c->request_method, "HEAD"); c->method_explicit = true; break;
                    case 'o':
                        if (argv[i][j + 1] != '\0') {
                            c->output_path = argv[i] + j + 1;
                            while (argv[i][j + 1] != '\0') j++;
                        } else {
                            handled = false;
                        }
                        break;
                    default: handled = false; break;
                }
                if (!handled) break;
            }
            if (handled) continue;
        }

        if (argv[i][0] == '-') { fprintf(stderr, "Unknown option: %s\n", argv[i]); exit(EXIT_FAILURE); }

        /* Collect all URL arguments */
        const char **new_urls = realloc(c->urls, (c->url_count + 1) * sizeof(*c->urls));
        if (new_urls == NULL) { fprintf(stderr, "Out of memory\n"); exit(EXIT_FAILURE); }
        c->urls = new_urls;
        c->urls[c->url_count++] = argv[i];
        if (c->input_url == NULL) c->input_url = argv[i];
        if (c->compare_urls_mode && c->compare_url == NULL && c->url_count >= 2)
            c->compare_url = argv[i];
        continue;
    }
}

/* --- Single request mode --- */
static int run_single_request(const struct cmdline_opts *c, struct run_options *opts,
                               struct run_result *result, FILE *body_out) {
    opts->follow_redirects = c->follow_redirects;
    strcpy(opts->method, c->request_method);
    opts->data = c->request_data;
    opts->address_family = c->address_family;
    opts->connect_timeout_ms = c->connect_timeout_ms;
    opts->read_timeout_ms = c->read_timeout_ms;
    opts->max_time_ms = c->max_time_ms;
    opts->max_redirects = c->max_redirects;
    opts->fail_on_http_error = c->fail_on_http_error;
    opts->body_out = body_out;
    opts->insecure_tls = c->insecure_tls;
    opts->basic_auth = c->basic_auth;
    opts->extra_headers = c->extra_headers;
    opts->extra_header_count = c->extra_header_count;
    opts->upload_path = c->upload_path;
    opts->happy_eyeballs = c->happy_eyeballs;
    opts->verbose = c->verbose;
    opts->user_agent = c->user_agent;
    opts->proxy_host = NULL;
    opts->proxy_port = NULL;
    opts->cookie_data = c->cookie_data;
    opts->cookie_jar_path = c->cookie_jar_path;
    opts->cookie_jar = NULL;
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

/* --- Compare family mode --- */
static int run_compare_family(const struct cmdline_opts *c, struct run_options *opts) {
    struct run_result result_v4, result_v6;
    bool ok_v4, ok_v6;

    opts->follow_redirects = c->follow_redirects;
    strcpy(opts->method, c->request_method);
    opts->data = c->request_data;
    opts->connect_timeout_ms = c->connect_timeout_ms;
    opts->read_timeout_ms = c->read_timeout_ms;
    opts->max_time_ms = c->max_time_ms;
    opts->max_redirects = c->max_redirects;
    opts->fail_on_http_error = c->fail_on_http_error;
    opts->body_out = NULL;
    opts->insecure_tls = c->insecure_tls;
    opts->basic_auth = c->basic_auth;
    opts->extra_headers = c->extra_headers;
    opts->extra_header_count = c->extra_header_count;
    opts->upload_path = NULL;
    opts->happy_eyeballs = c->happy_eyeballs;
    opts->verbose = c->verbose;
    opts->user_agent = c->user_agent;
    opts->proxy_host = NULL;
    opts->proxy_port = NULL;
    opts->cookie_data = c->cookie_data;
    opts->cookie_jar_path = c->cookie_jar_path;
    opts->cookie_jar = NULL;
    opts->resolve_entries = c->resolve_entries;
    opts->resolve_count = c->resolve_count;
    opts->referer = c->referer;
    opts->bind_interface = c->bind_interface;
    opts->tls_min_version = c->tls_min_version;
    opts->tls_max_version = c->tls_max_version;
    opts->retry_count = 0;
    opts->retry_delay_ms = 0;
    opts->compressed = c->compressed;
    opts->unix_socket_path = c->unix_socket_path;

    opts->address_family = AF_INET;
    struct run_options opts_v4 = *opts;
    opts_v4.address_family = AF_INET6;
    struct run_options opts_v6 = opts_v4;

    run_two_requests_parallel(c->input_url, &opts_v4, &result_v4, &ok_v4,
                               c->input_url, &opts_v6, &result_v6, &ok_v6);

    maybe_print_april_fools();
    if (c->wizard_mode) print_wizard_banner();
    if (c->fika_mode) print_fika_banner();

    printf("Compare mode:      IPv4 vs IPv6\n");
    printf("Input URL:         %s\n", c->input_url);
    printf("Follow redirects:  %s\n", c->follow_redirects ? "yes" : "no");
    printf("Max redirects:     %d\n", c->max_redirects);
    if (is_localhost_url(c->input_url))
        printf("IPv4 and IPv6 are both trapped inside your machine.\n");
    printf("\n");

    print_compare_family_run("IPv4 run", &result_v4, ok_v4);
    printf("\n");
    print_compare_family_run("IPv6 run", &result_v6, ok_v6);

    if (ok_v4 && ok_v6) {
        printf("\nDiff (IPv6 - IPv4):\n");
        print_compare_family_metric("DNS", result_v4.dns_ms, result_v6.dns_ms);
        print_compare_family_metric("TCP", result_v4.connect_ms, result_v6.connect_ms);
        print_compare_family_metric("TTFB", result_v4.ttfb_ms, result_v6.ttfb_ms);
        print_compare_family_metric("Total", result_v4.total_ms, result_v6.total_ms);

        double delta = result_v6.total_ms - result_v4.total_ms;
        if (delta > 0.1) printf("\nFaster path:       IPv4 (by %.2f ms)\n", delta);
        else if (delta < -0.1) printf("\nFaster path:       IPv6 (by %.2f ms)\n", -delta);
        else printf("\nFaster path:       tie\n");

        if (strcmp(result_v4.final_url, result_v6.final_url) != 0)
            printf("Final URL differs between runs.\n");
        if (final_status_code(&result_v4) != final_status_code(&result_v6))
            printf("HTTP status differs between runs.\n");
    } else {
        printf("\nComparison incomplete: one or both runs failed.\n");
        if (!c->silent || c->show_error) {
            if (!ok_v4 && result_v4.error[0] != '\0')
                fprintf(stderr, "IPv4 run failed: %s\n", result_v4.error);
            if (!ok_v6 && result_v6.error[0] != '\0')
                fprintf(stderr, "IPv6 run failed: %s\n", result_v6.error);
        }
    }

    if (ok_v4) free_run_result(&result_v4);
    if (ok_v6) free_run_result(&result_v6);

    return (ok_v4 && ok_v6) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* --- Compare URLs mode --- */
static int run_compare_urls(const struct cmdline_opts *c, struct run_options *opts) {
    struct run_result result_a, result_b;
    char endpoint_a[NI_MAXHOST + 16], endpoint_b[NI_MAXHOST + 16];
    char status_a[32], status_b[32];
    bool ok_a, ok_b;

    opts->follow_redirects = c->follow_redirects;
    strcpy(opts->method, c->request_method);
    opts->data = c->request_data;
    opts->address_family = c->address_family;
    opts->connect_timeout_ms = c->connect_timeout_ms;
    opts->read_timeout_ms = c->read_timeout_ms;
    opts->max_time_ms = c->max_time_ms;
    opts->max_redirects = c->max_redirects;
    opts->fail_on_http_error = c->fail_on_http_error;
    opts->body_out = NULL;
    opts->insecure_tls = c->insecure_tls;
    opts->basic_auth = c->basic_auth;
    opts->extra_headers = c->extra_headers;
    opts->extra_header_count = c->extra_header_count;
    opts->upload_path = NULL;
    opts->happy_eyeballs = c->happy_eyeballs;
    opts->verbose = c->verbose;
    opts->user_agent = c->user_agent;
    opts->proxy_host = NULL;
    opts->proxy_port = NULL;
    opts->cookie_data = c->cookie_data;
    opts->cookie_jar_path = c->cookie_jar_path;
    opts->cookie_jar = NULL;
    opts->resolve_entries = c->resolve_entries;
    opts->resolve_count = c->resolve_count;
    opts->referer = c->referer;
    opts->bind_interface = c->bind_interface;
    opts->tls_min_version = c->tls_min_version;
    opts->tls_max_version = c->tls_max_version;
    opts->retry_count = 0;
    opts->retry_delay_ms = 0;
    opts->compressed = c->compressed;
    opts->unix_socket_path = c->unix_socket_path;

    memset(&result_a, 0, sizeof(result_a));
    memset(&result_b, 0, sizeof(result_b));
    run_two_requests_parallel(c->input_url, opts, &result_a, &ok_a,
                               c->compare_url, opts, &result_b, &ok_b);

    if (ok_a) {
        final_endpoint(&result_a, endpoint_a, sizeof(endpoint_a));
        snprintf(status_a, sizeof(status_a), "%d", final_status_code(&result_a));
    } else {
        snprintf(endpoint_a, sizeof(endpoint_a), "n/a");
        snprintf(status_a, sizeof(status_a), "failed");
    }
    if (ok_b) {
        final_endpoint(&result_b, endpoint_b, sizeof(endpoint_b));
        snprintf(status_b, sizeof(status_b), "%d", final_status_code(&result_b));
    } else {
        snprintf(endpoint_b, sizeof(endpoint_b), "n/a");
        snprintf(status_b, sizeof(status_b), "failed");
    }

    maybe_print_april_fools();
    if (c->wizard_mode) print_wizard_banner();
    if (c->fika_mode) print_fika_banner();

    printf("Compare mode:      request profile A vs B\n");
    printf("Profile A URL:     %s\n", c->input_url);
    printf("Profile B URL:     %s\n", c->compare_url);
    printf("Follow redirects:  %s\n", c->follow_redirects ? "yes" : "no");
    printf("Address family:    %s\n", (c->address_family == AF_INET) ? "IPv4" :
                                      (c->address_family == AF_INET6) ? "IPv6" : "auto");

    printf("\n%-10s | %-24s | %-24s | %-20s\n", "Metric", "A", "B", "Delta (B - A)");
    printf("-----------+--------------------------+--------------------------+----------------------\n");
    print_compare_metric_row("DNS", ok_a ? result_a.dns_ms : -1.0, ok_b ? result_b.dns_ms : -1.0);
    print_compare_metric_row("TCP", ok_a ? result_a.connect_ms : -1.0, ok_b ? result_b.connect_ms : -1.0);
    print_compare_metric_row("TTFB", ok_a ? result_a.ttfb_ms : -1.0, ok_b ? result_b.ttfb_ms : -1.0);
    print_compare_metric_row("Total", ok_a ? result_a.total_ms : -1.0, ok_b ? result_b.total_ms : -1.0);
    print_compare_text_row("Status", status_a, status_b);
    print_compare_text_row("IP/Family", endpoint_a, endpoint_b);
    print_compare_text_row("Final URL", ok_a ? result_a.final_url : "n/a", ok_b ? result_b.final_url : "n/a");

    if (ok_a && ok_b) {
        double delta = result_b.total_ms - result_a.total_ms;
        if (delta > 0.1) printf("\nFaster profile:    A (by %.2f ms)\n", delta);
        else if (delta < -0.1) printf("\nFaster profile:    B (by %.2f ms)\n", -delta);
        else printf("\nFaster profile:    tie\n");
    } else {
        if (!ok_a && result_a.error[0] != '\0') printf("A error: %s\n", result_a.error);
        if (!ok_b && result_b.error[0] != '\0') printf("B error: %s\n", result_b.error);
        printf("\nComparison incomplete: one or both profiles failed.\n");
    }

    if (ok_a) free_run_result(&result_a);
    if (ok_b) free_run_result(&result_b);

    return (ok_a && ok_b) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* --- write-out expansion --- */
static void write_out_expand(const char *fmt, const struct run_result *result) {
    while (*fmt != '\0') {
        if (fmt[0] == '%' && fmt[1] == '{') {
            const char *start = fmt + 2;
            const char *end = strchr(start, '}');
            if (end != NULL) {
                size_t varlen = (size_t)(end - start);
                char varname[64];
                size_t cplen = varlen;
                if (cplen >= sizeof(varname)) cplen = sizeof(varname) - 1;
                memcpy(varname, start, cplen);
                varname[cplen] = '\0';

                if (strcmp(varname, "http_code") == 0) {
                    printf("%d", final_status_code(result));
                } else if (strcmp(varname, "time_total") == 0) {
                    printf("%.3f", result->total_ms / 1000.0);
                } else if (strcmp(varname, "time_namelookup") == 0) {
                    printf("%.3f", result->dns_ms / 1000.0);
                } else if (strcmp(varname, "time_connect") == 0) {
                    printf("%.3f", result->connect_ms / 1000.0);
                } else if (strcmp(varname, "time_starttransfer") == 0) {
                    printf("%.3f", result->ttfb_ms >= 0.0 ? result->ttfb_ms / 1000.0 : 0.0);
                } else if (strcmp(varname, "url_effective") == 0) {
                    printf("%s", result->final_url);
                } else if (strcmp(varname, "num_redirects") == 0) {
                    printf("%d", result->hop_count > 0 ? result->hop_count - 1 : 0);
                } else if (strcmp(varname, "redirect_url") == 0) {
                    if (result->hop_count > 0) {
                        const struct hop_info *h = &result->hops[result->hop_count - 1];
                        if (h->has_redirect_target)
                            printf("%s", h->redirect_to_host);
                    }
                } else {
                    printf("%%{%s}", varname);
                }
                fmt = end + 1;
                continue;
            }
        }
        if (*fmt == '\\') {
            switch (fmt[1]) {
                case 'n': putchar('\n'); fmt += 2; continue;
                case 'r': putchar('\r'); fmt += 2; continue;
                case 't': putchar('\t'); fmt += 2; continue;
                default: break;
            }
        }
        putchar(*fmt);
        fmt++;
    }
}

/* --- main --- */
int main(int argc, char **argv) {
    struct cmdline_opts c;
    parse_cmdline(argc, argv, &c);

    /* Apply TLS params globally before any TLS operation */
    g_tls_params.cacert = c.cacert;
    g_tls_params.capath = c.capath;

    /* Free allocated memory on exit */
    int exit_code = EXIT_SUCCESS;

    if (c.compare_family_mode && c.compare_urls_mode) {
        fprintf(stderr, "--compare and --compare-urls are mutually exclusive\n");
        exit_code = EXIT_FAILURE; goto cleanup;
    }
    if (c.output_path != NULL && c.output_remote_name) {
        fprintf(stderr, "-o and -O are mutually exclusive\n"); exit_code = EXIT_FAILURE; goto cleanup;
    }
    if ((c.output_path != NULL || c.output_remote_name) && (c.compare_family_mode || c.compare_urls_mode)) {
        fprintf(stderr, "-o/-O are only supported in single request mode\n"); exit_code = EXIT_FAILURE; goto cleanup;
    }
    if (c.upload_path != NULL && (c.compare_family_mode || c.compare_urls_mode)) {
        fprintf(stderr, "-T/--upload-file is only supported in single request mode\n"); exit_code = EXIT_FAILURE; goto cleanup;
    }
    if (c.upload_path != NULL && c.request_data != NULL) {
        fprintf(stderr, "-T/--upload-file cannot be combined with -d/--data\n"); exit_code = EXIT_FAILURE; goto cleanup;
    }
    if (c.basic_auth != NULL && strchr(c.basic_auth, ':') == NULL) {
        fprintf(stderr, "-u/--user must be in the form user:password\n"); exit_code = EXIT_FAILURE; goto cleanup;
    }
    if (c.upload_path != NULL) {
        if (c.method_explicit && strcasecmp(c.request_method, "PUT") != 0) {
            fprintf(stderr, "-T/--upload-file requires -X PUT or no -X flag\n"); exit_code = EXIT_FAILURE; goto cleanup;
        }
        if (!c.method_explicit) strcpy(c.request_method, "PUT");
    }
    if (c.request_data != NULL && !c.method_explicit) strcpy(c.request_method, "POST");
    if (c.lore_mode) {
        printf("ORIGIN STORY:\n");
        printf("Someone wanted better timing diagnostics.\n");
        printf("Things escalated.\n");
        goto cleanup;
    }
    if (!c.compare_family_mode && !c.compare_urls_mode && c.input_url == NULL &&
        (c.wizard_mode || c.fika_mode || c.debug_chaos)) {
        maybe_print_april_fools();
        if (c.wizard_mode) print_wizard_banner();
        if (c.fika_mode) print_fika_banner();
        if (c.debug_chaos) fprintf(stderr, "Segmentation fault (not really)\n");
        goto cleanup;
    }
    if (c.debug_chaos) fprintf(stderr, "Segmentation fault (not really)\n");

    /* Parse proxy URL */
    char proxy_host_buf[256] = "", proxy_port_buf[16] = "";
    const char *proxy_host = NULL, *proxy_port = NULL;
    if (c.proxy_url != NULL) {
        struct url_info proxy_ui;
        memset(&proxy_ui, 0, sizeof(proxy_ui));
        if (parse_url(c.proxy_url, &proxy_ui) != 0) {
            fprintf(stderr, "Invalid proxy URL: %s\n", c.proxy_url); exit_code = EXIT_FAILURE; goto cleanup;
        }
        strcpy(proxy_host_buf, proxy_ui.host);
        strcpy(proxy_port_buf, proxy_ui.port);
        proxy_host = proxy_host_buf;
        proxy_port = proxy_port_buf;
    }

    /* Add cookie data from -b as an extra header */
    if (c.cookie_data != NULL && c.cookie_data[0] != '\0') {
        size_t hlen = strlen(c.cookie_data) + 10;
        c.cookie_header_alloc = malloc(hlen);
        if (c.cookie_header_alloc != NULL) {
            size_t n = snprintf(c.cookie_header_alloc, hlen, "Cookie: %s", c.cookie_data);
            if (n < hlen) {
                const char **new_headers = realloc(c.extra_headers, (c.extra_header_count + 1) * sizeof(*c.extra_headers));
                if (new_headers != NULL) {
                    c.extra_headers = new_headers;
                    c.extra_headers[c.extra_header_count++] = c.cookie_header_alloc;
                } else {
                    free(c.cookie_header_alloc);
                    c.cookie_header_alloc = NULL;
                }
            } else {
                free(c.cookie_header_alloc);
                c.cookie_header_alloc = NULL;
            }
        }
    }

    /* Initialize cookie jar */
    struct cookie_jar cookie_jar;
    struct cookie_jar *cookie_jar_ptr = NULL;
    if (c.cookie_jar_path != NULL || c.cookie_data != NULL || c.cookie_file_to_load != NULL) {
        cookie_jar_init(&cookie_jar);
        cookie_jar_ptr = &cookie_jar;
        if (c.cookie_jar_path != NULL) cookie_jar_load(&cookie_jar, c.cookie_jar_path);
        if (c.cookie_file_to_load != NULL) cookie_jar_load(&cookie_jar, c.cookie_file_to_load);
    }

    configure_output_buffering();

    if (!c.compare_family_mode && !c.compare_urls_mode) {
        struct run_options opts;
        struct run_result result;
        FILE *body_out = NULL;
        char output_path_buf[1024];
        bool close_body = false;

        if (c.input_url == NULL) {
            fprintf(stderr, "Usage: %s [-L] [-4|-6] [-X GET|POST|PUT] [-d data] [-f] [-s] [-S] [-k] "
                    "[-u user:pass] [-H header] [-o file | -O] [-T file] "
                    "[--connect-timeout ms] [--read-timeout ms] [--no-happy-eyeballs] "
                    "[--max-redirs n] [--compressed] [--data-urlencode data] "
                    "[--cacert file] [--capath dir] [--unix-socket path] [-w fmt] "
                    "<url> [url2...]\n",
                    argv[0]);
            exit_code = EXIT_FAILURE; goto cleanup;
        }

        if (c.output_remote_name) {
            if (output_filename_from_url(c.input_url, output_path_buf, sizeof(output_path_buf)) != 0) {
                fprintf(stderr, "Failed to derive output filename from URL\n"); exit_code = EXIT_FAILURE; goto cleanup;
            }
            c.output_path = output_path_buf;
        }

        if (c.output_path != NULL) {
            if (strcmp(c.output_path, "-") == 0) { body_out = stdout; c.silent = true; }
            else {
                body_out = fopen(c.output_path, "wb");
                if (body_out == NULL) {
                    fprintf(stderr, "Unable to open output file '%s': %s\n", c.output_path, strerror(errno));
                    exit_code = EXIT_FAILURE; goto cleanup;
                }
                close_body = true;
            }
        }

        if (body_out == NULL && !isatty(fileno(stdout))) { body_out = stdout; c.silent = true; }

        memset(&opts, 0, sizeof(opts));
        opts.proxy_host = proxy_host;
        opts.proxy_port = proxy_port;
        opts.cookie_jar = cookie_jar_ptr;

        if (!c.silent && c.url_count > 0) {
            maybe_print_april_fools();
            if (c.wizard_mode) print_wizard_banner();
            if (c.fika_mode) print_fika_banner();
        }

        if (c.url_count > 1 && !c.silent)
            printf("=== Multi-URL mode: %d URLs ===\n", c.url_count);

        for (int ui = 0; ui < c.url_count; ui++) {
            c.input_url = c.urls[ui];
            memset(&result, 0, sizeof(result));

            if (c.url_count > 1 && !c.silent)
                printf("\n--- URL %d/%d: %s ---\n", ui + 1, c.url_count, c.input_url);

            int rc = run_single_request(&c, &opts, &result, body_out);

            if (c.write_out_format != NULL) {
                if (!c.silent || rc != 0) {
                    /* write-out output goes to stdout regardless of silent mode */
                }
                write_out_expand(c.write_out_format, &result);
            }

            if (!c.silent) {
                if (rc != 0)
                    print_single_output(&result);
                else
                    print_single_output(&result);
            }

            free_run_result(&result);

            if (rc != 0) {
                if (close_body) fclose(body_out);
                exit_code = EXIT_FAILURE;
                goto cleanup;
            }
        }

        if (cookie_jar_ptr != NULL && c.cookie_jar_path != NULL)
            cookie_jar_save(cookie_jar_ptr, c.cookie_jar_path);

        if (close_body) fclose(body_out);
        goto cleanup;
    }

    if (c.compare_family_mode) {
        struct run_options opts;
        memset(&opts, 0, sizeof(opts));
        opts.proxy_host = proxy_host;
        opts.proxy_port = proxy_port;
        opts.cookie_jar = cookie_jar_ptr;

        if (c.input_url == NULL) {
            fprintf(stderr, "Usage: %s --compare <url>\n", argv[0]); exit_code = EXIT_FAILURE; goto cleanup;
        }
        if (c.address_family != AF_UNSPEC) {
            fprintf(stderr, "--compare cannot be combined with -4 or -6\n"); exit_code = EXIT_FAILURE; goto cleanup;
        }

        if (!c.silent) {
            maybe_print_april_fools();
            if (c.wizard_mode) print_wizard_banner();
            if (c.fika_mode) print_fika_banner();
        }

        exit_code = run_compare_family(&c, &opts);
        goto cleanup;
    }

    {
        struct run_options opts;
        memset(&opts, 0, sizeof(opts));
        opts.proxy_host = proxy_host;
        opts.proxy_port = proxy_port;
        opts.cookie_jar = cookie_jar_ptr;

        if (c.input_url == NULL || c.compare_url == NULL) {
            fprintf(stderr, "Usage: %s --compare-urls <url-a> <url-b>\n", argv[0]); exit_code = EXIT_FAILURE; goto cleanup;
        }

        if (!c.silent) {
            maybe_print_april_fools();
            if (c.wizard_mode) print_wizard_banner();
            if (c.fika_mode) print_fika_banner();
        }

        exit_code = run_compare_urls(&c, &opts);
        goto cleanup;
    }

cleanup:
    free(c.extra_headers);
    free(c.request_data_alloc);
    if (c.request_data_urlencode_alloc != NULL && c.request_data_urlencode_alloc != c.request_data_alloc) {
        free(c.request_data_urlencode_alloc);
    }
    free(c.cookie_data_alloc);
    free(c.cookie_header_alloc);
    free(c.urls);
    return exit_code;
}
