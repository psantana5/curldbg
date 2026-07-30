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
#include <unistd.h>
#include <netinet/tcp.h>
#include <poll.h>

static bool stdout_is_redirected(void) {
    return !isatty(fileno(stdout));
}

static void configure_output_buffering(void) {
    if (!stdout_is_redirected()) { (void)setvbuf(stdout, NULL, _IOLBF, 0); return; }
    (void)setvbuf(stdout, NULL, _IOFBF, 64 * 1024);
}

/* --- main --- */
int main(int argc, char **argv) {
    int exit_code = EXIT_SUCCESS;
    struct cmdline_opts *c = calloc(1, sizeof(*c));
    if (c == NULL) die("calloc");
    struct cookie_jar *cookie_jar_ptr = NULL;
    struct run_options session_opts;
    memset(&session_opts, 0, sizeof(session_opts));
    int parse_rc = parse_cmdline(argc, argv, c);
    if (parse_rc < 0) {
        fprintf(stderr, "%s\n", c->error[0] != '\0' ? c->error : "Invalid command line");
        exit_code = EXIT_FAILURE;
        goto cleanup;
    }
    if (parse_rc > 0) {
        exit_code = EXIT_SUCCESS;
        goto cleanup;
    }

    /* Free allocated memory on exit */

    if (c->compare_family_mode && c->compare_urls_mode) {
        fprintf(stderr, "--compare and --compare-urls are mutually exclusive\n");
        exit_code = EXIT_FAILURE; goto cleanup;
    }
    if (c->output_path != NULL && c->output_remote_name) {
        fprintf(stderr, "-o and -O are mutually exclusive\n"); exit_code = EXIT_FAILURE; goto cleanup;
    }
    if ((c->output_path != NULL || c->output_remote_name) && (c->compare_family_mode || c->compare_urls_mode)) {
        fprintf(stderr, "-o/-O are only supported in single request mode\n"); exit_code = EXIT_FAILURE; goto cleanup;
    }
    if (c->upload_path != NULL && (c->compare_family_mode || c->compare_urls_mode)) {
        fprintf(stderr, "-T/--upload-file is only supported in single request mode\n"); exit_code = EXIT_FAILURE; goto cleanup;
    }
    if (c->upload_path != NULL && c->request_data != NULL) {
        fprintf(stderr, "-T/--upload-file cannot be combined with -d/--data\n"); exit_code = EXIT_FAILURE; goto cleanup;
    }
    if (c->basic_auth != NULL && strchr(c->basic_auth, ':') == NULL) {
        fprintf(stderr, "-u/--user must be in the form user:password\n"); exit_code = EXIT_FAILURE; goto cleanup;
    }
    if (c->upload_path != NULL) {
        if (c->method_explicit && strcasecmp(c->request_method, "PUT") != 0) {
            fprintf(stderr, "-T/--upload-file requires -X PUT or no -X flag\n"); exit_code = EXIT_FAILURE; goto cleanup;
        }
        if (!c->method_explicit) safe_strlcpy(c->request_method, "PUT", sizeof(c->request_method));
    }
    if (c->request_data != NULL && !c->method_explicit) safe_strlcpy(c->request_method, "POST", sizeof(c->request_method));

    /* Parse proxy URL */
    char proxy_host_buf[256] = "", proxy_port_buf[16] = "";
    const char *proxy_host = NULL, *proxy_port = NULL;
    if (c->proxy_url != NULL) {
        struct url_info proxy_ui;
        memset(&proxy_ui, 0, sizeof(proxy_ui));
        if (parse_url(c->proxy_url, &proxy_ui) != 0) {
            fprintf(stderr, "Invalid proxy URL: %s\n", c->proxy_url); exit_code = EXIT_FAILURE; goto cleanup;
        }
        safe_strlcpy(proxy_host_buf, proxy_ui.host, sizeof(proxy_host_buf));
        safe_strlcpy(proxy_port_buf, proxy_ui.port, sizeof(proxy_port_buf));
        proxy_host = proxy_host_buf;
        proxy_port = proxy_port_buf;
    }

    /* Add cookie data from -b as an extra header */
    if (c->cookie_data != NULL && c->cookie_data[0] != '\0') {
        size_t hlen = strlen(c->cookie_data) + 10;
        c->cookie_header_alloc = malloc(hlen);
        if (c->cookie_header_alloc != NULL) {
            size_t n = snprintf(c->cookie_header_alloc, hlen, "Cookie: %s", c->cookie_data);
            if (n < hlen) {
                const char **new_headers = realloc(c->extra_headers, (c->extra_header_count + 1) * sizeof(*c->extra_headers));
                if (new_headers != NULL) {
                    c->extra_headers = new_headers;
                    c->extra_headers[c->extra_header_count++] = c->cookie_header_alloc;
                } else {
                    free(c->cookie_header_alloc);
                    c->cookie_header_alloc = NULL;
                }
            } else {
                free(c->cookie_header_alloc);
                c->cookie_header_alloc = NULL;
            }
        }
    }

    /* Initialize cookie jar (heap-allocated; ~1.4 MB if fully populated) */
    if (c->cookie_jar_path != NULL || c->cookie_data != NULL || c->cookie_file_to_load != NULL) {
        cookie_jar_ptr = calloc(1, sizeof(*cookie_jar_ptr));
        if (cookie_jar_ptr == NULL) die("calloc");
        cookie_jar_init(cookie_jar_ptr);
        if (c->cookie_jar_path != NULL) cookie_jar_load(cookie_jar_ptr, c->cookie_jar_path);
        if (c->cookie_file_to_load != NULL) cookie_jar_load(cookie_jar_ptr, c->cookie_file_to_load);
    }

    configure_output_buffering();

    if (!c->compare_family_mode && !c->compare_urls_mode) {
        struct run_result result;
        struct connection_state rconn;
        FILE *body_out = NULL;
        char output_path_buf[1024];
        bool close_body = false;
        memset(&rconn, 0, sizeof(rconn));
        rconn.conn.fd = -1;

        if (c->input_url == NULL) {
            fprintf(stderr, "Usage: %s [-L] [-4|-6] [-X GET|POST|PUT] [-d data] [-f] [-s] [-S] [-k] "
                    "[-u user:pass] [-H header] [-o file | -O] [-T file] "
                    "[--connect-timeout ms] [--read-timeout ms] [--no-happy-eyeballs] "
                    "[--max-redirs n] [--compressed] [--data-urlencode data] "
                    "[--cacert file] [--capath dir] [--unix-socket path] [-w fmt] "
                    "<url> [url2...]\n",
                    argv[0]);
            exit_code = EXIT_FAILURE; goto cleanup;
        }

        if (c->output_remote_name) {
            if (output_filename_from_url(c->input_url, output_path_buf, sizeof(output_path_buf)) != 0) {
                fprintf(stderr, "Failed to derive output filename from URL\n"); exit_code = EXIT_FAILURE; goto cleanup;
            }
            c->output_path = output_path_buf;
        }

        if (c->output_path != NULL) {
            bool is_head = (strcasecmp(c->request_method, "HEAD") == 0);
            if (strcmp(c->output_path, "-") == 0) {
                if (!is_head) { body_out = stdout; c->silent = true; }
            } else {
                if (!is_head) {
                    body_out = fopen(c->output_path, "wb");
                    if (body_out == NULL) {
                        fprintf(stderr, "Unable to open output file '%s': %s\n", c->output_path, strerror(errno));
                        exit_code = EXIT_FAILURE; goto cleanup;
                    }
                    close_body = true;
                }
            }
        } else if (stdout_is_redirected()) {
            bool is_head = (strcasecmp(c->request_method, "HEAD") == 0);
            if (!is_head) {
                body_out = stdout;
                c->silent = true;
            }
        }

        session_opts.proxy_host = proxy_host;
        session_opts.proxy_port = proxy_port;
        session_opts.cookie_jar = cookie_jar_ptr;

        if (c->url_count > 1 && !c->silent)
            printf("=== Multi-URL mode: %d URLs ===\n", c->url_count);

        for (int ui = 0; ui < c->url_count; ui++) {
            c->input_url = c->urls[ui];
            memset(&result, 0, sizeof(result));

            if (c->url_count > 1 && !c->silent)
                printf("\n--- URL %d/%d: %s ---\n", ui + 1, c->url_count, c->input_url);

            int rc = run_single_request(c, &session_opts, &result, body_out, &rconn);

            if (c->write_out_format != NULL) {
                write_out_expand(c->write_out_format, &result);
            }

            if (result.is_head && result.resp.header_text[0] != '\0') {
                const char *h = result.resp.header_text;
                while (*h != '\0') {
                    const char *nl = strstr(h, "\r\n");
                    if (nl == NULL) { printf("%s\n", h); break; }
                    size_t line_len = (size_t)(nl - h);
                    printf("%.*s\n", (int)line_len, h);
                    h = nl + 2;
                    if (*h == '\0' || (h[0] == '\r' && h[1] == '\n')) break;
                }
                printf("\n");
            }
            if (!c->silent) {
                print_single_output(&result);
            }

            free_run_result(&result);

            if (rc != 0) {
                if (close_body) fclose(body_out);
                close_connection(&rconn.conn);
                freeaddrinfo(rconn.addrs);
                rconn.addrs = NULL;
                rconn.conn.fd = -1;
                exit_code = EXIT_FAILURE;
                goto cleanup;
            }
        }

        close_connection(&rconn.conn);
        freeaddrinfo(rconn.addrs);

        if (cookie_jar_ptr != NULL && c->cookie_jar_path != NULL)
            cookie_jar_save(cookie_jar_ptr, c->cookie_jar_path);

        if (close_body) fclose(body_out);
        goto cleanup;
    }

    if (c->compare_family_mode) {
        struct run_options opts;
        memset(&opts, 0, sizeof(opts));
        opts.proxy_host = proxy_host;
        opts.proxy_port = proxy_port;
        opts.cookie_jar = cookie_jar_ptr;

        if (c->input_url == NULL) {
            fprintf(stderr, "Usage: %s --compare <url>\n", argv[0]); exit_code = EXIT_FAILURE; goto cleanup;
        }
        if (c->address_family != AF_UNSPEC) {
            fprintf(stderr, "--compare cannot be combined with -4 or -6\n"); exit_code = EXIT_FAILURE; goto cleanup;
        }

        exit_code = run_compare_family(c, &opts);
        goto cleanup;
    }

    {
        struct run_options opts;
        memset(&opts, 0, sizeof(opts));
        opts.proxy_host = proxy_host;
        opts.proxy_port = proxy_port;
        opts.cookie_jar = cookie_jar_ptr;

        if (c->input_url == NULL || c->compare_url == NULL) {
            fprintf(stderr, "Usage: %s --compare-urls <url-a> <url-b>\n", argv[0]); exit_code = EXIT_FAILURE; goto cleanup;
        }

        exit_code = run_compare_urls(c, &opts);
        goto cleanup;
    }

cleanup:
    tls_context_free(session_opts.tls_ctx);
    dns_cache_destroy(session_opts.dns_cache);
    free(c->extra_headers);
    free(c->request_data_alloc);
    if (c->request_data_urlencode_alloc != NULL && c->request_data_urlencode_alloc != c->request_data_alloc) {
        free(c->request_data_urlencode_alloc);
    }
    free(c->cookie_data_alloc);
    free(c->cookie_header_alloc);
    free(c->urls);
    free(cookie_jar_ptr);
    free(c);
    return exit_code;
}
