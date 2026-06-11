#include "curldbg.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct run_options {
    char method[8];
    const char *data;
    bool follow_redirects;
    int address_family;
    int connect_timeout_ms;
    int read_timeout_ms;
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

static int run_request(
    const char *input_url,
    const struct run_options *opts,
    struct run_result *out
);
static void *run_request_thread(void *arg);
static void run_two_requests_parallel(
    const char *url_a,
    const struct run_options *opts_a,
    struct run_result *result_a,
    bool *ok_a,
    const char *url_b,
    const struct run_options *opts_b,
    struct run_result *result_b,
    bool *ok_b
);
static int output_filename_from_url(const char *input_url, char *out, size_t out_size);

static int parse_non_negative_int(const char *value, const char *flag_name) {
    char *end = NULL;
    long parsed;

    if (value == NULL || *value == '\0') {
        fprintf(stderr, "Missing value for %s\n", flag_name);
        exit(EXIT_FAILURE);
    }

    parsed = strtol(value, &end, 10);
    if (*end != '\0' || parsed < 0 || parsed > 3600000) {
        fprintf(stderr, "Invalid value for %s: %s\n", flag_name, value);
        exit(EXIT_FAILURE);
    }

    return (int)parsed;
}

static void close_upload_file(FILE **file) {
    if (file != NULL && *file != NULL) {
        fclose(*file);
        *file = NULL;
    }
}

static bool is_loopback_ip(const char *ip) {
    return ip != NULL && (strcmp(ip, "127.0.0.1") == 0 || strcmp(ip, "::1") == 0);
}

static bool is_localhost_url(const char *input_url) {
    struct url_info url;

    if (input_url == NULL) {
        return false;
    }
    if (parse_url(input_url, &url) != 0) {
        return false;
    }
    return strcmp(url.host, "localhost") == 0 ||
           strcmp(url.host, "127.0.0.1") == 0 ||
           strcmp(url.host, "::1") == 0;
}

static void configure_output_buffering(void) {
    if (isatty(fileno(stdout))) {
        (void)setvbuf(stdout, NULL, _IOLBF, 0);
        return;
    }
    (void)setvbuf(stdout, NULL, _IOFBF, 64 * 1024);
}

static void maybe_print_april_fools(void) {
    static bool printed = false;
    time_t now;
    struct tm local_tm;

    if (printed) {
        return;
    }
    now = time(NULL);
    if (now == (time_t)-1) {
        return;
    }
    if (localtime_r(&now, &local_tm) == NULL) {
        return;
    }
    if (local_tm.tm_mon == 3 && local_tm.tm_mday == 1) {
        printf("HTTP/3 disabled due to mercury retrograde\n");
        printed = true;
    }
}

static void print_wizard_banner(void) {
    printf("You are now entering advanced networking wizard mode.\n");
    printf("Latency is temporary. Packets are eternal.\n");
    printf("OH NOW WE'RE TALKING 😭💀\n");
}

static void print_fika_banner(void) {
    printf("Pausing requests for mandatory Swedish coffee break...\n");
}

static int output_filename_from_url(const char *input_url, char *out, size_t out_size) {
    struct url_info url;
    const char *path;
    const char *segment;
    const char *slash;
    char name_buf[1024];
    char *cut;
    int n;

    if (parse_url(input_url, &url) != 0) {
        return -1;
    }

    path = url.path;
    slash = strrchr(path, '/');
    segment = (slash != NULL) ? slash + 1 : path;

    if (segment[0] == '\0') {
        n = snprintf(out, out_size, "index.html");
        return (n < 0 || (size_t)n >= out_size) ? -1 : 0;
    }

    snprintf(name_buf, sizeof(name_buf), "%s", segment);
    cut = strpbrk(name_buf, "?#");
    if (cut != NULL) {
        *cut = '\0';
    }
    if (name_buf[0] == '\0') {
        n = snprintf(out, out_size, "index.html");
    } else {
        n = snprintf(out, out_size, "%s", name_buf);
    }

    return (n < 0 || (size_t)n >= out_size) ? -1 : 0;
}

static void free_run_result(struct run_result *result) {
    free(result->hops);
    result->hops = NULL;
    result->hop_count = 0;
}

static int final_status_code(const struct run_result *result) {
    if (result->hop_count <= 0) {
        return 0;
    }
    return result->hops[result->hop_count - 1].status_code;
}

static void final_endpoint(const struct run_result *result, char *out, size_t out_size) {
    if (result->hop_count <= 0) {
        snprintf(out, out_size, "n/a");
        return;
    }

    {
        const struct hop_info *hop = &result->hops[result->hop_count - 1];
        snprintf(out, out_size, "%s (%s)", hop->connected_ip, family_name(hop->connected_family));
    }
}

static const char *family_short_name(int family) {
    if (family == AF_INET) {
        return "v4";
    }
    if (family == AF_INET6) {
        return "v6";
    }
    return "?";
}

static void *run_request_thread(void *arg) {
    struct run_request_task *task = (struct run_request_task *)arg;
    task->ok = (run_request(task->url, task->opts, task->result) == 0);
    return NULL;
}

static void run_two_requests_parallel(
    const char *url_a,
    const struct run_options *opts_a,
    struct run_result *result_a,
    bool *ok_a,
    const char *url_b,
    const struct run_options *opts_b,
    struct run_result *result_b,
    bool *ok_b
) {
    struct run_request_task task_a = {.url = url_a, .opts = opts_a, .result = result_a, .ok = false};
    struct run_request_task task_b = {.url = url_b, .opts = opts_b, .result = result_b, .ok = false};
    pthread_t thread_a;
    pthread_t thread_b;
    bool thread_a_started = false;
    bool thread_b_started = false;

    if (pthread_create(&thread_a, NULL, run_request_thread, &task_a) == 0) {
        thread_a_started = true;
    } else {
        task_a.ok = (run_request(url_a, opts_a, result_a) == 0);
    }

    if (pthread_create(&thread_b, NULL, run_request_thread, &task_b) == 0) {
        thread_b_started = true;
    } else {
        task_b.ok = (run_request(url_b, opts_b, result_b) == 0);
    }

    if (thread_a_started) {
        (void)pthread_join(thread_a, NULL);
    }
    if (thread_b_started) {
        (void)pthread_join(thread_b, NULL);
    }

    *ok_a = task_a.ok;
    *ok_b = task_b.ok;
}

static int run_request(
    const char *input_url,
    const struct run_options *opts,
    struct run_result *out
) {
    char current_url[2048];
    char next_url[2048];
    int redirect_count = 0;
    FILE *upload_file = NULL;
    size_t upload_size = 0;
    struct timespec total_start, total_end;

    memset(out, 0, sizeof(*out));
    out->ttfb_ms = -1.0;
    out->error[0] = '\0';

    if (strlen(input_url) >= sizeof(current_url)) {
        snprintf(out->error, sizeof(out->error), "URL too long");
        return -1;
    }
    strcpy(current_url, input_url);

    if (opts->upload_path != NULL) {
        struct stat st;
        upload_file = fopen(opts->upload_path, "rb");
        if (upload_file == NULL) {
            snprintf(out->error, sizeof(out->error), "Unable to open upload file '%s': %s",
                     opts->upload_path, strerror(errno));
            return -1;
        }
        if (stat(opts->upload_path, &st) != 0) {
            snprintf(out->error, sizeof(out->error), "Unable to stat upload file '%s': %s",
                     opts->upload_path, strerror(errno));
            close_upload_file(&upload_file);
            return -1;
        }
        if (st.st_size < 0) {
            snprintf(out->error, sizeof(out->error), "Upload file size is invalid");
            close_upload_file(&upload_file);
            return -1;
        }
        if ((unsigned long long)st.st_size > (unsigned long long)SIZE_MAX) {
            snprintf(out->error, sizeof(out->error), "Upload file is too large");
            close_upload_file(&upload_file);
            return -1;
        }
        upload_size = (size_t)st.st_size;
    }

    out->hops = calloc((size_t)opts->max_redirects + 1, sizeof(*out->hops));
    if (out->hops == NULL) {
        die("calloc");
    }

    if (clock_gettime(CLOCK_MONOTONIC, &total_start) != 0) {
        die("clock_gettime");
    }

    for (;;) {
        struct url_info url;
        struct url_info redirected_url;
        struct addrinfo *addrs = NULL;
        int fd;
        int gai_error = 0;
        struct connection conn;
        struct connect_race_info race_info;
        struct timespec dns_start, dns_end;
        struct timespec connect_start, connect_end;
        struct timespec ttfb_start;
        bool can_redirect = false;

        if (parse_url(current_url, &url) != 0) {
            snprintf(out->error, sizeof(out->error), "Invalid URL: %s", current_url);
            free_run_result(out);
            close_upload_file(&upload_file);
            return -1;
        }
        if (out->hop_count >= opts->max_redirects + 1) {
            snprintf(out->error, sizeof(out->error), "Too many hops");
            free_run_result(out);
            close_upload_file(&upload_file);
            return -1;
        }
        memset(&out->hops[out->hop_count], 0, sizeof(out->hops[out->hop_count]));

        if (clock_gettime(CLOCK_MONOTONIC, &dns_start) != 0) {
            die("clock_gettime");
        }
        addrs = resolve_dns(&url, opts->address_family, &gai_error);
        if (clock_gettime(CLOCK_MONOTONIC, &dns_end) != 0) {
            die("clock_gettime");
        }
        if (addrs == NULL) {
            snprintf(out->error, sizeof(out->error), "DNS resolution failed: %s", gai_strerror(gai_error));
            free_run_result(out);
            close_upload_file(&upload_file);
            return -1;
        }
        out->dns_ms += ms_between(&dns_start, &dns_end);

        if (clock_gettime(CLOCK_MONOTONIC, &connect_start) != 0) {
            die("clock_gettime");
        }
        fd = connect_tcp(
            addrs,
            out->hops[out->hop_count].connected_ip,
            sizeof(out->hops[out->hop_count].connected_ip),
            &out->hops[out->hop_count].connected_family,
            opts->connect_timeout_ms,
            &race_info,
            opts->happy_eyeballs
        );
        if (clock_gettime(CLOCK_MONOTONIC, &connect_end) != 0) {
            die("clock_gettime");
        }
        if (fd < 0) {
            snprintf(out->error, sizeof(out->error), "TCP connect failed: %s", strerror(errno));
            freeaddrinfo(addrs);
            free_run_result(out);
            close_upload_file(&upload_file);
            return -1;
        }
        if (race_info.winner_connect_ms > 0.0) {
            out->connect_ms += race_info.winner_connect_ms;
        } else {
            out->connect_ms += ms_between(&connect_start, &connect_end);
        }

        conn.fd = fd;
        conn.use_tls = url.use_tls;
        conn.ctx = NULL;
        conn.ssl = NULL;
        conn.verbose = opts->verbose;

        apply_socket_timeout(conn.fd, opts->read_timeout_ms);

        if (url.use_tls) {
            if (init_tls(&conn, url.host, opts->insecure_tls, out->error, sizeof(out->error)) != 0) {
                close_connection(&conn);
                freeaddrinfo(addrs);
                free_run_result(out);
                close_upload_file(&upload_file);
                return -1;
            }
        }

        if (clock_gettime(CLOCK_MONOTONIC, &ttfb_start) != 0) {
            die("clock_gettime");
        }
        if (upload_file != NULL) {
            if (fseeko(upload_file, 0, SEEK_SET) != 0) {
                snprintf(out->error, sizeof(out->error), "Failed to rewind upload file");
                close_connection(&conn);
                freeaddrinfo(addrs);
                free_run_result(out);
                close_upload_file(&upload_file);
                return -1;
            }
        }
        if (send_request(
                &conn,
                &url,
                opts->method,
                opts->data,
                upload_file,
                upload_size,
                opts->extra_headers,
                opts->extra_header_count,
                opts->basic_auth,
                out->error,
                sizeof(out->error)
            ) != 0) {
            close_connection(&conn);
            freeaddrinfo(addrs);
            free_run_result(out);
            close_upload_file(&upload_file);
            return -1;
        }
        if (receive_response(
                &conn,
                &ttfb_start,
                &out->resp,
                out->error,
                sizeof(out->error),
                opts->body_out,
                opts->follow_redirects,
                opts->fail_on_http_error
            ) != 0) {
            close_connection(&conn);
            freeaddrinfo(addrs);
            free_run_result(out);
            close_upload_file(&upload_file);
            return -1;
        }
        if (opts->fail_on_http_error && out->resp.status_code >= 400) {
            snprintf(out->error, sizeof(out->error), "HTTP %d", out->resp.status_code);
            close_connection(&conn);
            freeaddrinfo(addrs);
            free_run_result(out);
            close_upload_file(&upload_file);
            return -1;
        }
        out->ttfb_ms = out->resp.ttfb_ms;

        snprintf(out->hops[out->hop_count].host, sizeof(out->hops[out->hop_count].host), "%s", url.host);
        out->hops[out->hop_count].status_code = out->resp.status_code;
        out->hops[out->hop_count].dns_ms = ms_between(&dns_start, &dns_end);
        if (race_info.winner_connect_ms > 0.0) {
            out->hops[out->hop_count].tcp_ms = race_info.winner_connect_ms;
        } else {
            out->hops[out->hop_count].tcp_ms = ms_between(&connect_start, &connect_end);
        }
        out->hops[out->hop_count].ttfb_ms = out->resp.ttfb_ms;
        out->hops[out->hop_count].has_loser = race_info.has_loser;
        if (race_info.has_loser) {
            snprintf(
                out->hops[out->hop_count].loser_ip,
                sizeof(out->hops[out->hop_count].loser_ip),
                "%s",
                race_info.loser_ip
            );
            out->hops[out->hop_count].loser_family = race_info.loser_family;
            out->hops[out->hop_count].loser_connect_ms = race_info.loser_connect_ms;
        }

        if (is_redirect_status(out->resp.status_code) && out->resp.location[0] != '\0' &&
            build_redirect_url(out->resp.location, &url, next_url, sizeof(next_url)) == 0 &&
            parse_url(next_url, &redirected_url) == 0) {
            snprintf(
                out->hops[out->hop_count].redirect_to_host,
                sizeof(out->hops[out->hop_count].redirect_to_host),
                "%s",
                redirected_url.host
            );
            out->hops[out->hop_count].has_redirect_target = true;
            can_redirect = true;
        }

        close_connection(&conn);
        freeaddrinfo(addrs);

        out->hop_count++;

        if (!opts->follow_redirects || !can_redirect) {
            if (format_url(&url, out->final_url, sizeof(out->final_url)) != 0) {
                snprintf(out->final_url, sizeof(out->final_url), "%s", current_url);
            }
            break;
        }

        if (redirect_count >= opts->max_redirects) {
            snprintf(out->error, sizeof(out->error), "Too many redirects (limit %d)", opts->max_redirects);
            free_run_result(out);
            close_upload_file(&upload_file);
            return -1;
        }

        strcpy(current_url, next_url);
        redirect_count++;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &total_end) != 0) {
        die("clock_gettime");
    }
    out->total_ms = ms_between(&total_start, &total_end);
    close_upload_file(&upload_file);
    return 0;
}

static void print_single_output(const struct run_result *result) {
    char endpoint[NI_MAXHOST + 16];
    const struct hop_info *final_hop = NULL;
    int status_code = final_status_code(result);

    final_endpoint(result, endpoint, sizeof(endpoint));
    if (result->hop_count > 0) {
        final_hop = &result->hops[result->hop_count - 1];
    }

    printf("DNS lookup:        %.2f ms\n", result->dns_ms);
    printf("TCP connect:       %.2f ms\n", result->connect_ms);
    if (result->ttfb_ms >= 0.0) {
        printf("TTFB:              %.2f ms\n", result->ttfb_ms);
    } else {
        printf("TTFB:              n/a (no response bytes)\n");
    }
    printf("Total:             %.2f ms\n", result->total_ms);
    if (status_code > 0) {
        printf("HTTP status:       %d\n", status_code);
    }
    printf("Endpoint:          %s\n", endpoint);
    if (final_hop != NULL && is_loopback_ip(final_hop->connected_ip)) {
        printf("Congratulations, you found yourself.\n");
    }
    if (status_code == 418) {
        printf("The server acknowledges your coffee infrastructure.\n");
    }
    if (result->ttfb_ms >= 0.0 && result->ttfb_ms < 5.0) {
        printf("WARNING: request arrived before it was sent\n");
    }
    if (result->dns_ms >= 2000.0) {
        printf("DNS resolver currently communicating through astral plane\n");
    }
    if (final_hop != NULL && final_hop->has_loser && final_hop->loser_connect_ms >= 0.0) {
        printf(
            "Other:             %s (%s, %+0.2f ms)\n",
            final_hop->loser_ip,
            family_short_name(final_hop->loser_family),
            final_hop->loser_connect_ms - final_hop->tcp_ms
        );
    }
    printf("Final URL:         %s\n", result->final_url);

    printf("\nRedirect chain:\n");
    for (int i = 0; i < result->hop_count; i++) {
        if (result->hops[i].has_redirect_target) {
            printf(
                "[%d] %s -> %s\n",
                result->hops[i].status_code,
                result->hops[i].host,
                result->hops[i].redirect_to_host
            );
        } else {
            printf("[%d] %s\n", result->hops[i].status_code, result->hops[i].host);
        }
    }
    if (result->hop_count > 7) {
        printf("Redirect chain resembles enterprise architecture.\n");
    }

    printf("\nPer-hop timing:\n");
    for (int i = 0; i < result->hop_count; i++) {
        printf("Hop %d:\n", i + 1);
        printf("  DNS: %.2f ms\n", result->hops[i].dns_ms);
        printf("  TCP: %.2f ms\n", result->hops[i].tcp_ms);
        if (result->hops[i].ttfb_ms >= 0.0) {
            printf("  TTFB: %.2f ms\n", result->hops[i].ttfb_ms);
        } else {
            printf("  TTFB: n/a\n");
        }
        printf(
            "  Connected to: %s (%s)\n",
            result->hops[i].connected_ip,
            family_name(result->hops[i].connected_family)
        );
        if (result->hops[i].has_loser && result->hops[i].loser_connect_ms >= 0.0) {
            printf(
                "  Other: %s (%s, %+0.2f ms)\n",
                result->hops[i].loser_ip,
                family_short_name(result->hops[i].loser_family),
                result->hops[i].loser_connect_ms - result->hops[i].tcp_ms
            );
        }
    }

    printf("\nResponse body preview (first ~1KB):\n");
    if (result->resp.preview_len > 0) {
        fwrite(result->resp.preview, 1, result->resp.preview_len, stdout);
        if (result->resp.preview[result->resp.preview_len - 1] != '\n') {
            putchar('\n');
        }
    } else {
        printf("(empty)\n");
    }
}

static void print_compare_metric_row(const char *metric, double a, double b) {
    char a_buf[48];
    char b_buf[48];
    char delta_buf[64];

    if (a >= 0.0) {
        snprintf(a_buf, sizeof(a_buf), "%.2f ms", a);
    } else {
        snprintf(a_buf, sizeof(a_buf), "n/a");
    }

    if (b >= 0.0) {
        snprintf(b_buf, sizeof(b_buf), "%.2f ms", b);
    } else {
        snprintf(b_buf, sizeof(b_buf), "n/a");
    }

    if (a >= 0.0 && b >= 0.0) {
        double delta = b - a;
        if (a > 0.0) {
            double pct = (delta / a) * 100.0;
            snprintf(delta_buf, sizeof(delta_buf), "%+.2f ms (%+.1f%%)", delta, pct);
        } else {
            snprintf(delta_buf, sizeof(delta_buf), "%+.2f ms", delta);
        }
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

    if (v4 < 0.0 || v6 < 0.0) {
        printf("  %-14s n/a\n", label);
        return;
    }

    if (v4 > 0.0) {
        double pct = (delta / v4) * 100.0;
        printf("  %-14s %+8.2f ms (%+.1f%%)\n", label, delta, pct);
    } else {
        printf("  %-14s %+8.2f ms\n", label, delta);
    }
}

static void print_compare_family_run(const char *name, const struct run_result *result, bool ok) {
    printf("%s:\n", name);
    if (!ok) {
        printf("  status: failed\n");
        if (result->error[0] != '\0') {
            printf("  error: %s\n", result->error);
        }
        return;
    }

    printf("  status: %d\n", final_status_code(result));
    printf("  total: %.2f ms\n", result->total_ms);
    printf("  dns: %.2f ms\n", result->dns_ms);
    printf("  tcp: %.2f ms\n", result->connect_ms);
    if (result->ttfb_ms >= 0.0) {
        printf("  ttfb: %.2f ms\n", result->ttfb_ms);
    } else {
        printf("  ttfb: n/a\n");
    }

    if (result->hop_count > 0) {
        const struct hop_info *last_hop = &result->hops[result->hop_count - 1];
        printf("  connected: %s (%s)\n", last_hop->connected_ip, family_name(last_hop->connected_family));
    } else {
        printf("  connected: n/a\n");
    }
    printf("  final url: %s\n", result->final_url);
}

int main(int argc, char **argv) {
    const char *input_url = NULL;
    const char *compare_url = NULL;
    char request_method[8] = "GET";
    bool method_explicit = false;
    const char *request_data = NULL;
    char *request_data_alloc = NULL;
    bool compare_family_mode = false;
    bool compare_urls_mode = false;
    bool follow_redirects = false;
    bool fail_on_http_error = false;
    bool silent = false;
    bool show_error = false;
    const char *output_path = NULL;
    bool output_remote_name = false;
    bool insecure_tls = false;
    const char *basic_auth = NULL;
    const char *upload_path = NULL;
    const char **extra_headers = NULL;
    size_t extra_header_count = 0;
    bool wizard_mode = false;
    bool debug_chaos = false;
    bool lore_mode = false;
    bool fika_mode = false;
    bool happy_eyeballs = true;
    bool verbose = false;
    int address_family = AF_UNSPEC;
    int connect_timeout_ms = 0;
    int read_timeout_ms = 0;
    int max_redirects = DEFAULT_MAX_REDIRECTS;

    configure_output_buffering();

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--compare") == 0) {
            compare_family_mode = true;
            continue;
        }
        if (strcmp(argv[i], "--compare-urls") == 0) {
            compare_urls_mode = true;
            continue;
        }
        if (strcmp(argv[i], "--version") == 0) {
            printf("curldbg %s\n", CURLDBG_VERSION);
            printf("Author: Pau Santana\n");
            free(extra_headers);
            free(request_data_alloc);
            return EXIT_SUCCESS;
        }
        if (strcmp(argv[i], "--wizard") == 0) {
            wizard_mode = true;
            continue;
        }
        if (strcmp(argv[i], "--debug-chaos") == 0) {
            debug_chaos = true;
            continue;
        }
        if (strcmp(argv[i], "--lore") == 0) {
            lore_mode = true;
            continue;
        }
        if (strcmp(argv[i], "--fika") == 0) {
            fika_mode = true;
            continue;
        }
        if (strcmp(argv[i], "--no-happy-eyeballs") == 0) {
            happy_eyeballs = false;
            continue;
        }
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
            continue;
        }
        if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--insecure") == 0) {
            insecure_tls = true;
            continue;
        }
        if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--user") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing value for %s\n", argv[i]);
                return EXIT_FAILURE;
            }
            basic_auth = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "-H") == 0 || strcmp(argv[i], "--header") == 0) {
            const char *header_value;
            const char **next_headers;
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing value for %s\n", argv[i]);
                return EXIT_FAILURE;
            }
            header_value = argv[++i];
            if (strchr(header_value, '\r') != NULL || strchr(header_value, '\n') != NULL) {
                fprintf(stderr, "Invalid header value (newline detected)\n");
                return EXIT_FAILURE;
            }
            next_headers = realloc(extra_headers, (extra_header_count + 1) * sizeof(*extra_headers));
            if (next_headers == NULL) {
                fprintf(stderr, "Out of memory\n");
                return EXIT_FAILURE;
            }
            extra_headers = next_headers;
            extra_headers[extra_header_count++] = header_value;
            continue;
        }
        if (strcmp(argv[i], "-T") == 0 || strcmp(argv[i], "--upload-file") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing value for %s\n", argv[i]);
                return EXIT_FAILURE;
            }
            if (upload_path != NULL) {
                fprintf(stderr, "Only one upload file is supported\n");
                return EXIT_FAILURE;
            }
            upload_path = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--fail") == 0) {
            fail_on_http_error = true;
            continue;
        }
        if (strcmp(argv[i], "--progress-bar") == 0) {
            continue;
        }
        if (strcmp(argv[i], "-I") == 0 || strcmp(argv[i], "--head") == 0) {
            strcpy(request_method, "HEAD");
            method_explicit = true;
            continue;
        }
        if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--silent") == 0) {
            silent = true;
            continue;
        }
        if (strcmp(argv[i], "-S") == 0 || strcmp(argv[i], "--show-error") == 0) {
            show_error = true;
            continue;
        }
        if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing value for %s\n", argv[i]);
                return EXIT_FAILURE;
            }
            output_path = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "-O") == 0 || strcmp(argv[i], "--remote-name") == 0) {
            output_remote_name = true;
            continue;
        }
        if (strcmp(argv[i], "-X") == 0 || strcmp(argv[i], "--request") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing value for %s\n", argv[i]);
                return EXIT_FAILURE;
            }
            i++;
            if (strcasecmp(argv[i], "GET") == 0) {
                strcpy(request_method, "GET");
            } else if (strcasecmp(argv[i], "POST") == 0) {
                strcpy(request_method, "POST");
            } else if (strcasecmp(argv[i], "PUT") == 0) {
                strcpy(request_method, "PUT");
            } else {
                fprintf(stderr, "Only GET, POST, and PUT are supported for -X/--request\n");
                return EXIT_FAILURE;
            }
            method_explicit = true;
            continue;
        }
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--data") == 0 || strcmp(argv[i], "--data-binary") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing value for %s\n", argv[i]);
                free(request_data_alloc);
                return EXIT_FAILURE;
            }
            i++;
            if (argv[i][0] == '@') {
                const char *spec = argv[i] + 1;
                FILE *fp = NULL;
                char buf[4096];
                size_t cap = 4096;
                size_t total = 0;
                size_t nread;
                char *data;
                bool close_fp = false;

                if (spec[0] == '-' && spec[1] == '\0') {
                    fp = stdin;
                } else {
                    fp = fopen(spec, "rb");
                    if (fp == NULL) {
                        fprintf(stderr, "Unable to open data file '%s': %s\n", spec, strerror(errno));
                        free(extra_headers);
                        free(request_data_alloc);
                        return EXIT_FAILURE;
                    }
                    close_fp = true;
                }

                data = malloc(cap);
                if (data == NULL) {
                    fprintf(stderr, "Out of memory reading data\n");
                    if (close_fp) fclose(fp);
                    free(extra_headers);
                    free(request_data_alloc);
                    return EXIT_FAILURE;
                }

                while ((nread = fread(buf, 1, sizeof(buf), fp)) > 0) {
                    if (total + nread >= cap) {
                        cap = (cap > SIZE_MAX / 2) ? SIZE_MAX : cap * 2;
                        char *tmp = realloc(data, cap);
                        if (tmp == NULL) {
                            fprintf(stderr, "Out of memory reading data\n");
                            free(data);
                            if (close_fp) fclose(fp);
                            free(extra_headers);
                            free(request_data_alloc);
                            return EXIT_FAILURE;
                        }
                        data = tmp;
                    }
                    memcpy(data + total, buf, nread);
                    total += nread;
                }

                if (ferror(fp)) {
                    fprintf(stderr, "Failed to read data from '%s'\n", spec);
                    free(data);
                    if (close_fp) fclose(fp);
                    free(extra_headers);
                    free(request_data_alloc);
                    return EXIT_FAILURE;
                }

                if (close_fp) fclose(fp);
                data[total] = '\0';

                if (request_data != NULL) {
                    char *combined = malloc(strlen(request_data) + 1 + total + 1);
                    if (combined == NULL) {
                        fprintf(stderr, "Out of memory\n");
                        free(data);
                        free(extra_headers);
                        free(request_data_alloc);
                        return EXIT_FAILURE;
                    }
                    snprintf(combined, strlen(request_data) + 1 + total + 1, "%s&%s", request_data, data);
                    free(request_data_alloc);
                    free(data);
                    request_data = combined;
                    request_data_alloc = combined;
                } else {
                    free(request_data_alloc);
                    request_data = data;
                    request_data_alloc = data;
                }
            } else {
                if (request_data != NULL) {
                    size_t new_len = strlen(request_data) + 1 + strlen(argv[i]) + 1;
                    char *combined = malloc(new_len);
                    if (combined == NULL) {
                        fprintf(stderr, "Out of memory\n");
                        free(extra_headers);
                        free(request_data_alloc);
                        return EXIT_FAILURE;
                    }
                    snprintf(combined, new_len, "%s&%s", request_data, argv[i]);
                    free(request_data_alloc);
                    request_data = combined;
                    request_data_alloc = combined;
                } else {
                    request_data = argv[i];
                }
            }
            continue;
        }
        if (strcmp(argv[i], "-L") == 0 || strcmp(argv[i], "--location") == 0) {
            follow_redirects = true;
            continue;
        }
        if (strcmp(argv[i], "-4") == 0) {
            if (address_family == AF_INET6) {
                fprintf(stderr, "-4 and -6 are mutually exclusive\n");
                return EXIT_FAILURE;
            }
            address_family = AF_INET;
            continue;
        }
        if (strcmp(argv[i], "-6") == 0) {
            if (address_family == AF_INET) {
                fprintf(stderr, "-4 and -6 are mutually exclusive\n");
                return EXIT_FAILURE;
            }
            address_family = AF_INET6;
            continue;
        }
        if (strcmp(argv[i], "--connect-timeout") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing value for --connect-timeout\n");
                return EXIT_FAILURE;
            }
            connect_timeout_ms = parse_non_negative_int(argv[++i], "--connect-timeout");
            continue;
        }
        if (strcmp(argv[i], "--no-happy-eyeballs") == 0) {
            happy_eyeballs = false;
            continue;
        }
        if (strcmp(argv[i], "--read-timeout") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing value for --read-timeout\n");
                return EXIT_FAILURE;
            }
            read_timeout_ms = parse_non_negative_int(argv[++i], "--read-timeout");
            continue;
        }
        if (strcmp(argv[i], "--max-redirs") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing value for --max-redirs\n");
                return EXIT_FAILURE;
            }
            max_redirects = parse_non_negative_int(argv[++i], "--max-redirs");
            continue;
        }

        if (argv[i][0] == '-' && argv[i][1] != '\0' && argv[i][1] != '-' && argv[i][2] != '\0') {
            bool handled = true;
            for (size_t j = 1; argv[i][j] != '\0'; j++) {
                switch (argv[i][j]) {
                    case 'f':
                        fail_on_http_error = true;
                        break;
                    case 's':
                        silent = true;
                        break;
                    case 'S':
                        show_error = true;
                        break;
                    case 'v':
                        verbose = true;
                        break;
                    case 'k':
                        insecure_tls = true;
                        break;
                    case 'L':
                        follow_redirects = true;
                        break;
                    case 'I':
                        strcpy(request_method, "HEAD");
                        method_explicit = true;
                        break;
                    default:
                        handled = false;
                        break;
                }
                if (!handled) {
                    break;
                }
            }
            if (handled) {
                continue;
            }
        }

        if (argv[i][0] == '-') {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return EXIT_FAILURE;
        }

        if (input_url == NULL) {
            input_url = argv[i];
            continue;
        }
        if (compare_urls_mode && compare_url == NULL) {
            compare_url = argv[i];
            continue;
        }

        fprintf(stderr, "Too many URL arguments\n");
        return EXIT_FAILURE;
    }

    if (compare_family_mode && compare_urls_mode) {
        fprintf(stderr, "--compare and --compare-urls are mutually exclusive\n");
        free(extra_headers);
        free(request_data_alloc);
        return EXIT_FAILURE;
    }
    if (output_path != NULL && output_remote_name) {
        fprintf(stderr, "-o and -O are mutually exclusive\n");
        free(extra_headers);
        free(request_data_alloc);
        return EXIT_FAILURE;
    }
    if ((output_path != NULL || output_remote_name) && (compare_family_mode || compare_urls_mode)) {
        fprintf(stderr, "-o/-O are only supported in single request mode\n");
        free(extra_headers);
        free(request_data_alloc);
        return EXIT_FAILURE;
    }
    if (upload_path != NULL && (compare_family_mode || compare_urls_mode)) {
        fprintf(stderr, "-T/--upload-file is only supported in single request mode\n");
        free(extra_headers);
        free(request_data_alloc);
        return EXIT_FAILURE;
    }
    if (upload_path != NULL && request_data != NULL) {
        fprintf(stderr, "-T/--upload-file cannot be combined with -d/--data\n");
        free(extra_headers);
        free(request_data_alloc);
        return EXIT_FAILURE;
    }
    if (basic_auth != NULL && strchr(basic_auth, ':') == NULL) {
        fprintf(stderr, "-u/--user must be in the form user:password\n");
        free(extra_headers);
        free(request_data_alloc);
        return EXIT_FAILURE;
    }
    if (upload_path != NULL) {
        if (method_explicit && strcasecmp(request_method, "PUT") != 0) {
            fprintf(stderr, "-T/--upload-file requires -X PUT or no -X flag\n");
            free(extra_headers);
        free(request_data_alloc);
            return EXIT_FAILURE;
        }
        if (!method_explicit) {
            strcpy(request_method, "PUT");
        }
    }
    if (request_data != NULL && !method_explicit) {
        strcpy(request_method, "POST");
    }
    if (lore_mode) {
        printf("ORIGIN STORY:\n");
        printf("Someone wanted better timing diagnostics.\n");
        printf("Things escalated.\n");
        free(extra_headers);
        free(request_data_alloc);
        return EXIT_SUCCESS;
    }
    if (!compare_family_mode && !compare_urls_mode && input_url == NULL && compare_url == NULL &&
        (wizard_mode || fika_mode || debug_chaos)) {
        maybe_print_april_fools();
        if (wizard_mode) {
            print_wizard_banner();
        }
        if (fika_mode) {
            print_fika_banner();
        }
        if (debug_chaos) {
            fprintf(stderr, "Segmentation fault (not really)\n");
        }
        free(extra_headers);
        free(request_data_alloc);
        return EXIT_SUCCESS;
    }
    if (debug_chaos) {
        fprintf(stderr, "Segmentation fault (not really)\n");
    }

    if (!compare_family_mode && !compare_urls_mode) {
        struct run_options opts;
        struct run_result result;
        FILE *body_out = NULL;
        char output_path_buf[1024];
        bool close_body = false;

        if (input_url == NULL || compare_url != NULL) {
            fprintf(
                stderr,
                "Usage: %s [-L] [-4|-6] [-X GET|POST|PUT] [-d data] [-f] [-s] [-S] [-k] [-u user:pass] "
                "[-H header] [-o file | -O] [-T file] "
                "[--connect-timeout ms] [--read-timeout ms] [--no-happy-eyeballs] "
                "[--max-redirs n] <url>\n"
                "  URL may be http://..., https://..., or bare host/path (defaults to https)\n",
                argv[0]
            );
            return EXIT_FAILURE;
        }

        if (output_remote_name) {
            if (output_filename_from_url(input_url, output_path_buf, sizeof(output_path_buf)) != 0) {
                fprintf(stderr, "Failed to derive output filename from URL\n");
                return EXIT_FAILURE;
            }
            output_path = output_path_buf;
        }

        if (output_path != NULL) {
            if (strcmp(output_path, "-") == 0) {
                body_out = stdout;
                silent = true;
            } else {
                body_out = fopen(output_path, "wb");
                if (body_out == NULL) {
                    fprintf(stderr, "Unable to open output file '%s': %s\n", output_path, strerror(errno));
                    return EXIT_FAILURE;
                }
                close_body = true;
            }
        }

        if (body_out == NULL && !isatty(fileno(stdout))) {
            body_out = stdout;
            silent = true;
        }

        opts.follow_redirects = follow_redirects;
        strcpy(opts.method, request_method);
        opts.data = request_data;
        opts.address_family = address_family;
        opts.connect_timeout_ms = connect_timeout_ms;
        opts.read_timeout_ms = read_timeout_ms;
        opts.max_redirects = max_redirects;
        opts.fail_on_http_error = fail_on_http_error;
        opts.body_out = body_out;
        opts.insecure_tls = insecure_tls;
        opts.basic_auth = basic_auth;
        opts.extra_headers = extra_headers;
        opts.extra_header_count = extra_header_count;
        opts.upload_path = upload_path;
        opts.happy_eyeballs = happy_eyeballs;
        opts.verbose = verbose;

        if (!silent) {
            maybe_print_april_fools();
            if (wizard_mode) {
                print_wizard_banner();
            }
            if (fika_mode) {
                print_fika_banner();
            }
        }

        if (run_request(input_url, &opts, &result) != 0) {
            if ((!silent || show_error) && result.error[0] != '\0') {
                fprintf(stderr, "Request failed: %s\n", result.error);
            }
            if (close_body) {
                fclose(body_out);
            }
            return EXIT_FAILURE;
        }

        if (!silent) {
            print_single_output(&result);
        }
        free_run_result(&result);
        if (close_body) {
            fclose(body_out);
        }
        free(extra_headers);
        free(request_data_alloc);
        return EXIT_SUCCESS;
    }

    if (compare_family_mode) {
        struct run_options opts_v4;
        struct run_options opts_v6;
        struct run_result result_v4;
        struct run_result result_v6;
        bool ok_v4;
        bool ok_v6;
        double total_delta;

        if (input_url == NULL || compare_url != NULL) {
            fprintf(
                stderr,
                "Usage: %s --compare [-L] [-X GET|POST|PUT] [-d data] [-f] [-s] [-S] [-k] [-u user:pass] "
                "[-H header] [--connect-timeout ms] [--no-happy-eyeballs] "
                "[--read-timeout ms] [--max-redirs n] "
                "<url>\n",
                argv[0]
            );
            return EXIT_FAILURE;
        }
        if (address_family != AF_UNSPEC) {
            fprintf(stderr, "--compare cannot be combined with -4 or -6\n");
            return EXIT_FAILURE;
        }

        opts_v4.follow_redirects = follow_redirects;
        strcpy(opts_v4.method, request_method);
        opts_v4.data = request_data;
        opts_v4.address_family = AF_INET;
        opts_v4.connect_timeout_ms = connect_timeout_ms;
        opts_v4.read_timeout_ms = read_timeout_ms;
        opts_v4.max_redirects = max_redirects;
        opts_v4.fail_on_http_error = fail_on_http_error;
        opts_v4.body_out = NULL;
        opts_v4.insecure_tls = insecure_tls;
        opts_v4.basic_auth = basic_auth;
        opts_v4.extra_headers = extra_headers;
        opts_v4.extra_header_count = extra_header_count;
        opts_v4.upload_path = NULL;
        opts_v4.happy_eyeballs = happy_eyeballs;
        opts_v4.verbose = verbose;

        opts_v6 = opts_v4;
        opts_v6.address_family = AF_INET6;

        run_two_requests_parallel(
            input_url,
            &opts_v4,
            &result_v4,
            &ok_v4,
            input_url,
            &opts_v6,
            &result_v6,
            &ok_v6
        );

        if (!silent) {
            maybe_print_april_fools();
            if (wizard_mode) {
                print_wizard_banner();
            }
            if (fika_mode) {
                print_fika_banner();
            }
            printf("Compare mode:      IPv4 vs IPv6\n");
            printf("Input URL:         %s\n", input_url);
            printf("Follow redirects:  %s\n", follow_redirects ? "yes" : "no");
            printf("Max redirects:     %d\n", max_redirects);
            if (is_localhost_url(input_url)) {
                printf("IPv4 and IPv6 are both trapped inside your machine.\n");
            }
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

                total_delta = result_v6.total_ms - result_v4.total_ms;
                if (total_delta > 0.1) {
                    printf("\nFaster path:       IPv4 (by %.2f ms)\n", total_delta);
                } else if (total_delta < -0.1) {
                    printf("\nFaster path:       IPv6 (by %.2f ms)\n", -total_delta);
                } else {
                    printf("\nFaster path:       tie\n");
                }

                if (strcmp(result_v4.final_url, result_v6.final_url) != 0) {
                    printf("Final URL differs between runs.\n");
                }
                if (final_status_code(&result_v4) != final_status_code(&result_v6)) {
                    printf("HTTP status differs between runs.\n");
                }
            } else {
                printf("\nComparison incomplete: one or both runs failed.\n");
            }
        } else if (!silent || show_error) {
            if (!ok_v4 && result_v4.error[0] != '\0') {
                fprintf(stderr, "IPv4 run failed: %s\n", result_v4.error);
            }
            if (!ok_v6 && result_v6.error[0] != '\0') {
                fprintf(stderr, "IPv6 run failed: %s\n", result_v6.error);
            }
        }

        if (ok_v4) {
            free_run_result(&result_v4);
        }
        if (ok_v6) {
            free_run_result(&result_v6);
        }
        free(extra_headers);
        free(request_data_alloc);

        return (ok_v4 && ok_v6) ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    {
        struct run_options opts;
        struct run_result result_a;
        struct run_result result_b;
        char endpoint_a[NI_MAXHOST + 16];
        char endpoint_b[NI_MAXHOST + 16];
        char status_a[32];
        char status_b[32];
        double total_delta;
        bool ok_a;
        bool ok_b;

        if (input_url == NULL || compare_url == NULL) {
            fprintf(
                stderr,
                "Usage: %s --compare-urls [-L] [-4|-6] [-X GET|POST|PUT] [-d data] [-f] [-s] [-S] [-k] "
                "[-u user:pass] [-H header] "
                "[--connect-timeout ms] [--read-timeout ms] [--no-happy-eyeballs] "
                "[--max-redirs n] <url-a> <url-b>\n",
                argv[0]
            );
            return EXIT_FAILURE;
        }

        opts.follow_redirects = follow_redirects;
        strcpy(opts.method, request_method);
        opts.data = request_data;
        opts.address_family = address_family;
        opts.connect_timeout_ms = connect_timeout_ms;
        opts.read_timeout_ms = read_timeout_ms;
        opts.max_redirects = max_redirects;
        opts.fail_on_http_error = fail_on_http_error;
        opts.body_out = NULL;
        opts.insecure_tls = insecure_tls;
        opts.basic_auth = basic_auth;
        opts.extra_headers = extra_headers;
        opts.extra_header_count = extra_header_count;
        opts.upload_path = NULL;
        opts.happy_eyeballs = happy_eyeballs;
        opts.verbose = verbose;

        memset(&result_a, 0, sizeof(result_a));
        memset(&result_b, 0, sizeof(result_b));
        run_two_requests_parallel(
            input_url,
            &opts,
            &result_a,
            &ok_a,
            compare_url,
            &opts,
            &result_b,
            &ok_b
        );

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

        if (!silent) {
            maybe_print_april_fools();
            if (wizard_mode) {
                print_wizard_banner();
            }
            if (fika_mode) {
                print_fika_banner();
            }
            printf("Compare mode:      request profile A vs B\n");
            printf("Profile A URL:     %s\n", input_url);
            printf("Profile B URL:     %s\n", compare_url);
            printf("Follow redirects:  %s\n", follow_redirects ? "yes" : "no");
            printf("Address family:    %s\n", (address_family == AF_INET) ? "IPv4" :
                                             (address_family == AF_INET6) ? "IPv6" : "auto");

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
                total_delta = result_b.total_ms - result_a.total_ms;
                if (total_delta > 0.1) {
                    printf("\nFaster profile:    A (by %.2f ms)\n", total_delta);
                } else if (total_delta < -0.1) {
                    printf("\nFaster profile:    B (by %.2f ms)\n", -total_delta);
                } else {
                    printf("\nFaster profile:    tie\n");
                }
            } else {
                if (!ok_a && result_a.error[0] != '\0') {
                    printf("A error: %s\n", result_a.error);
                }
                if (!ok_b && result_b.error[0] != '\0') {
                    printf("B error: %s\n", result_b.error);
                }
                printf("\nComparison incomplete: one or both profiles failed.\n");
            }
        } else if (!silent || show_error) {
            if (!ok_a && result_a.error[0] != '\0') {
                fprintf(stderr, "A run failed: %s\n", result_a.error);
            }
            if (!ok_b && result_b.error[0] != '\0') {
                fprintf(stderr, "B run failed: %s\n", result_b.error);
            }
        }

        if (ok_a) {
            free_run_result(&result_a);
        }
        if (ok_b) {
            free_run_result(&result_b);
        }
        free(extra_headers);
        free(request_data_alloc);
        return (ok_a && ok_b) ? EXIT_SUCCESS : EXIT_FAILURE;
    }
}
