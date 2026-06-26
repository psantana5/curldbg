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
#include <poll.h>

static int output_filename_from_url(const char *input_url, char *out, size_t out_size);

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

/* --- Compare family mode --- */
static int run_compare_family(const struct cmdline_opts *c, struct run_options *opts) {
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
                write_out_expand(c.write_out_format, &result);
            }

            if (!c.silent) {
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
