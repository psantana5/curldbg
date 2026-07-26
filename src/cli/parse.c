#include "curldbg.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>

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

void parse_cmdline(int argc, char **argv, struct cmdline_opts *c) {
    if (c == NULL) return;
    memset(c, 0, sizeof(*c));
    c->happy_eyeballs = true;
    c->max_redirects = DEFAULT_MAX_REDIRECTS;
    c->address_family = AF_UNSPEC;
    strcpy(c->request_method, "GET");

    signal(SIGPIPE, SIG_IGN);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            for (i++; i < argc; i++) {
                const char **new_urls = realloc(c->urls, (c->url_count + 1) * sizeof(*c->urls));
                if (new_urls == NULL) { fprintf(stderr, "Out of memory\n"); exit(EXIT_FAILURE); }
                c->urls = new_urls;
                c->urls[c->url_count++] = argv[i];
                if (c->input_url == NULL) c->input_url = argv[i];
                if (c->compare_urls_mode && c->compare_url == NULL && c->url_count >= 2)
                    c->compare_url = argv[i];
            }
            break;
        }
        if (strcmp(argv[i], "--compare") == 0) { c->compare_family_mode = true; continue; }
        if (strcmp(argv[i], "--compare-urls") == 0) { c->compare_urls_mode = true; continue; }
        if (strcmp(argv[i], "--version") == 0) {
            printf("curldbg %s\n", CURLDBG_VERSION);
            printf("Author: Pau Santana\n"); exit(EXIT_SUCCESS);
        }
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help(argv[0]); exit(EXIT_SUCCESS);
        }
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
                if (c->request_data != NULL) {
                    size_t old_len = c->request_data_len;
                    char *combined = malloc(old_len + 1 + total + 1);
                    if (combined == NULL) { free(data); fprintf(stderr, "Out of memory\n"); exit(EXIT_FAILURE); }
                    memcpy(combined, c->request_data, old_len);
                    combined[old_len] = '&';
                    memcpy(combined + old_len + 1, data, total);
                    combined[old_len + 1 + total] = '\0';
                    free(c->request_data_alloc); free(data);
                    c->request_data = combined; c->request_data_alloc = combined;
                    c->request_data_len = old_len + 1 + total;
                    c->request_data_urlencode_alloc = NULL;
                } else {
                    free(c->request_data_alloc);
                    c->request_data = data; c->request_data_alloc = data;
                    c->request_data_len = total;
                    c->request_data_urlencode_alloc = NULL;
                }
            } else {
                size_t arg_len = strlen(argv[i]);
                if (c->request_data != NULL) {
                    size_t old_len = c->request_data_len;
                    size_t new_len = old_len + 1 + arg_len + 1;
                    char *combined = malloc(new_len);
                    if (combined == NULL) { fprintf(stderr, "Out of memory\n"); exit(EXIT_FAILURE); }
                    memcpy(combined, c->request_data, old_len);
                    combined[old_len] = '&';
                    memcpy(combined + old_len + 1, argv[i], arg_len);
                    combined[old_len + 1 + arg_len] = '\0';
                    free(c->request_data_alloc);
                    c->request_data = combined; c->request_data_alloc = combined;
                    c->request_data_len = old_len + 1 + arg_len;
                    c->request_data_urlencode_alloc = NULL;
                } else {
                    c->request_data = argv[i];
                    c->request_data_len = arg_len;
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
            if (arg[0] == '@') {
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
                content = arg + 1;
            } else {
                const char *at = strchr(arg, '@');
                const char *eq = strchr(arg, '=');
                if (eq != NULL && (at == NULL || eq < at)) {
                    size_t nlen = (size_t)(eq - arg);
                    char *n = malloc(nlen + 1);
                    if (n == NULL) { fprintf(stderr, "Out of memory\n"); exit(EXIT_FAILURE); }
                    memcpy(n, arg, nlen); n[nlen] = '\0';
                    name = n;
                    content = eq + 1;
                } else if (at != NULL) {
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
                    content = arg;
                }
            }
            size_t clen = strlen(content);
            size_t max_encoded = clen * 3 + 1;
            encoded = malloc(max_encoded);
            if (encoded == NULL) { fprintf(stderr, "Out of memory\n"); free(file_buf); exit(EXIT_FAILURE); }
            if (url_encode(content, encoded, max_encoded) != 0) {
                fprintf(stderr, "URL-encoding failed\n"); free(encoded); free(file_buf); exit(EXIT_FAILURE);
            }
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
                    case 'O': c->output_remote_name = true; break;
                    case 'I': strcpy(c->request_method, "HEAD"); c->method_explicit = true; break;
                    case 'h': print_help(argv[0]); exit(EXIT_SUCCESS);
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

        const char **new_urls = realloc(c->urls, (c->url_count + 1) * sizeof(*c->urls));
        if (new_urls == NULL) { fprintf(stderr, "Out of memory\n"); exit(EXIT_FAILURE); }
        c->urls = new_urls;
        c->urls[c->url_count++] = argv[i];
        if (c->input_url == NULL) c->input_url = argv[i];
        if (c->compare_urls_mode && c->compare_url == NULL && c->url_count >= 2)
            c->compare_url = argv[i];
    }
}
