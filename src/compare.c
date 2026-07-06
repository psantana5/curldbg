#include "curldbg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool is_localhost_url(const char *input_url) {
    struct url_info url;
    if (input_url == NULL) return false;
    if (parse_url(input_url, &url) != 0) return false;
    return strcmp(url.host, "localhost") == 0 ||
           strcmp(url.host, "127.0.0.1") == 0 ||
           strcmp(url.host, "::1") == 0;
}

int run_compare_family(const struct cmdline_opts *c, struct run_options *opts) {
    struct run_result result_v4, result_v6;
    bool ok_v4, ok_v6;

    init_run_options(opts, c);
    opts->body_out = NULL;
    opts->upload_path = NULL;
    opts->proxy_host = NULL;
    opts->proxy_port = NULL;
    opts->cookie_jar = NULL;
    opts->retry_count = 0;
    opts->retry_delay_ms = 0;

    opts->address_family = AF_INET;
    struct run_options opts_v4 = *opts;
    opts->address_family = AF_INET6;
    struct run_options opts_v6 = *opts;

    run_two_requests_parallel(c->input_url, &opts_v4, &result_v4, &ok_v4,
                               c->input_url, &opts_v6, &result_v6, &ok_v6);

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

int run_compare_urls(const struct cmdline_opts *c, struct run_options *opts) {
    struct run_result result_a, result_b;
    char endpoint_a[NI_MAXHOST + 16], endpoint_b[NI_MAXHOST + 16];
    char status_a[32], status_b[32];
    bool ok_a, ok_b;

    init_run_options(opts, c);
    opts->body_out = NULL;
    opts->upload_path = NULL;
    opts->proxy_host = NULL;
    opts->proxy_port = NULL;
    opts->cookie_jar = NULL;
    opts->retry_count = 0;
    opts->retry_delay_ms = 0;

    memset(&result_a, 0, sizeof(result_a));
    memset(&result_b, 0, sizeof(result_b));
    run_two_requests_parallel(c->input_url, opts, &result_a, &ok_a,
                               c->compare_url, opts, &result_b, &ok_b);

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
