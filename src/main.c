#include "curldbg.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

struct run_options {
    char method[8];
    const char *data;
    bool follow_redirects;
    int address_family;
    int connect_timeout_ms;
    int read_timeout_ms;
    int max_redirects;
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
    struct timespec total_start, total_end;

    memset(out, 0, sizeof(*out));
    out->ttfb_ms = -1.0;
    out->error[0] = '\0';

    if (strlen(input_url) >= sizeof(current_url)) {
        snprintf(out->error, sizeof(out->error), "URL too long");
        return -1;
    }
    strcpy(current_url, input_url);

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
            return -1;
        }
        if (out->hop_count >= opts->max_redirects + 1) {
            snprintf(out->error, sizeof(out->error), "Too many hops");
            free_run_result(out);
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
            &race_info
        );
        if (clock_gettime(CLOCK_MONOTONIC, &connect_end) != 0) {
            die("clock_gettime");
        }
        if (fd < 0) {
            snprintf(out->error, sizeof(out->error), "TCP connect failed: %s", strerror(errno));
            freeaddrinfo(addrs);
            free_run_result(out);
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

        apply_socket_timeout(conn.fd, opts->read_timeout_ms);

        if (url.use_tls) {
            if (init_tls(&conn, url.host, out->error, sizeof(out->error)) != 0) {
                close_connection(&conn);
                freeaddrinfo(addrs);
                free_run_result(out);
                return -1;
            }
        }

        if (clock_gettime(CLOCK_MONOTONIC, &ttfb_start) != 0) {
            die("clock_gettime");
        }
        if (send_request(
                &conn,
                &url,
                opts->method,
                opts->data,
                out->error,
                sizeof(out->error)
            ) != 0) {
            close_connection(&conn);
            freeaddrinfo(addrs);
            free_run_result(out);
            return -1;
        }
        if (receive_response(&conn, &ttfb_start, &out->resp, out->error, sizeof(out->error)) != 0) {
            close_connection(&conn);
            freeaddrinfo(addrs);
            free_run_result(out);
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
            return -1;
        }

        strcpy(current_url, next_url);
        redirect_count++;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &total_end) != 0) {
        die("clock_gettime");
    }
    out->total_ms = ms_between(&total_start, &total_end);
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
    bool compare_family_mode = false;
    bool compare_urls_mode = false;
    bool follow_redirects = false;
    int address_family = AF_UNSPEC;
    int connect_timeout_ms = 0;
    int read_timeout_ms = 0;
    int max_redirects = DEFAULT_MAX_REDIRECTS;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--compare") == 0) {
            compare_family_mode = true;
            continue;
        }
        if (strcmp(argv[i], "--compare-urls") == 0) {
            compare_urls_mode = true;
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
            } else {
                fprintf(stderr, "Only GET and POST are supported for -X/--request\n");
                return EXIT_FAILURE;
            }
            method_explicit = true;
            continue;
        }
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--data") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing value for %s\n", argv[i]);
                return EXIT_FAILURE;
            }
            request_data = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "-L") == 0) {
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
        return EXIT_FAILURE;
    }
    if (request_data != NULL && !method_explicit) {
        strcpy(request_method, "POST");
    }

    if (!compare_family_mode && !compare_urls_mode) {
        struct run_options opts;
        struct run_result result;

        if (input_url == NULL || compare_url != NULL) {
            fprintf(
                stderr,
                "Usage: %s [-L] [-4|-6] [-X GET|POST] [-d data] "
                "[--connect-timeout ms] [--read-timeout ms] "
                "[--max-redirs n] <url>\n"
                "  URL may be http://..., https://..., or bare host/path (defaults to https)\n",
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

        if (run_request(input_url, &opts, &result) != 0) {
            if (result.error[0] != '\0') {
                fprintf(stderr, "Request failed: %s\n", result.error);
            }
            return EXIT_FAILURE;
        }

        print_single_output(&result);
        free_run_result(&result);
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
                "Usage: %s --compare [-L] [-X GET|POST] [-d data] [--connect-timeout ms] "
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

        printf("Compare mode:      IPv4 vs IPv6\n");
        printf("Input URL:         %s\n", input_url);
        printf("Follow redirects:  %s\n", follow_redirects ? "yes" : "no");
        printf("Max redirects:     %d\n", max_redirects);
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

        if (ok_v4) {
            free_run_result(&result_v4);
        }
        if (ok_v6) {
            free_run_result(&result_v6);
        }

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
                "Usage: %s --compare-urls [-L] [-4|-6] [-X GET|POST] [-d data] "
                "[--connect-timeout ms] [--read-timeout ms] "
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

        if (ok_a) {
            free_run_result(&result_a);
        }
        if (ok_b) {
            free_run_result(&result_b);
        }
        return (ok_a && ok_b) ? EXIT_SUCCESS : EXIT_FAILURE;
    }
}
