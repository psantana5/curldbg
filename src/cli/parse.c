#include "curldbg.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>

#define MAX_DATA_FILE_SIZE (16 * 1024 * 1024)

static void copy_bounded(char *dst, size_t dst_size, const char *src) {
    size_t len = strlen(src);
    if (len >= dst_size) len = dst_size - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

static void set_cmdline_error(struct cmdline_opts *c, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(c->error, sizeof(c->error), fmt, ap);
    va_end(ap);
}

static char *read_data_file(FILE *fp, size_t *out_len) {
    size_t cap = 4096, total = 0;
    char *data = malloc(cap);
    if (data == NULL) return NULL;
    char buf[4096];
    size_t nread;
    while ((nread = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (total + nread > MAX_DATA_FILE_SIZE) {
            free(data);
            return NULL;
        }
        if (total + nread >= cap) {
            cap = (cap > SIZE_MAX / 2) ? SIZE_MAX : cap * 2;
            char *tmp = realloc(data, cap);
            if (tmp == NULL) { free(data); return NULL; }
            data = tmp;
        }
        memcpy(data + total, buf, nread);
        total += nread;
    }
    if (ferror(fp)) { free(data); return NULL; }
    data[total] = '\0';
    if (out_len != NULL) *out_len = total;
    return data;
}

static int parse_non_negative_int(const char *value, const char *flag_name,
                                  struct cmdline_opts *c, int *ok) {
    char *end = NULL;
    long parsed;
    *ok = 0;
    if (value == NULL || *value == '\0') {
        set_cmdline_error(c, "Missing value for %s", flag_name); return 0;
    }
    parsed = strtol(value, &end, 10);
    if (*end != '\0' || parsed < 0 || parsed > 3600000) {
        set_cmdline_error(c, "Invalid value for %s: %s", flag_name, value); return 0;
    }
    *ok = 1;
    return (int)parsed;
}

static int parse_nn(struct cmdline_opts *c, const char *flag_name,
                    const char *value, const char *desc) {
    int ok;
    int v = parse_non_negative_int(value, flag_name, c, &ok);
    if (!ok) {
        set_cmdline_error(c, "%s", desc);
        return -1;
    }
    return v;
}

int parse_cmdline(int argc, char **argv, struct cmdline_opts *c) {
    if (c == NULL) return -1;
    memset(c, 0, sizeof(*c));
    c->happy_eyeballs = true;
    c->max_redirects = DEFAULT_MAX_REDIRECTS;
    c->address_family = AF_UNSPEC;
    snprintf(c->request_method, sizeof(c->request_method), "GET");

    signal(SIGPIPE, SIG_IGN);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            for (i++; i < argc; i++) {
                const char **new_urls = realloc(c->urls, (c->url_count + 1) * sizeof(*c->urls));
                if (new_urls == NULL) { set_cmdline_error(c, "Out of memory"); return -1; }
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
            printf("Author: Pau Santana\n"); return 1;
        }
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help(argv[0]); return 1;
        }
        if (strcmp(argv[i], "--no-happy-eyeballs") == 0) { c->happy_eyeballs = false; continue; }
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) { c->verbose = true; continue; }
        if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--insecure") == 0) { c->insecure_tls = true; continue; }
        if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--user") == 0) {
            if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for %s", argv[i]); return -1; }
            c->basic_auth = argv[++i];
            if (contains_crlf(c->basic_auth)) {
                set_cmdline_error(c, "Invalid value for %s (newline detected)", argv[i - 1]); return -1;
            }
            continue;
        }
        if (strcmp(argv[i], "-A") == 0 || strcmp(argv[i], "--user-agent") == 0) {
            if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for %s", argv[i]); return -1; }
            c->user_agent = argv[++i];
            if (contains_crlf(c->user_agent)) {
                set_cmdline_error(c, "Invalid value for %s (newline detected)", argv[i - 1]); return -1;
            }
            continue;
        }
        if (strcmp(argv[i], "-H") == 0 || strcmp(argv[i], "--header") == 0) {
            const char *header_value;
            if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for %s", argv[i]); return -1; }
            header_value = argv[++i];
            if (strchr(header_value, '\r') != NULL || strchr(header_value, '\n') != NULL) {
                set_cmdline_error(c, "Invalid header value (newline detected)"); return -1;
            }
            const char **next = realloc(c->extra_headers, (c->extra_header_count + 1) * sizeof(*c->extra_headers));
            if (next == NULL) { set_cmdline_error(c, "Out of memory"); return -1; }
            c->extra_headers = next;
            c->extra_headers[c->extra_header_count++] = header_value;
            continue;
        }
        if (strcmp(argv[i], "-T") == 0 || strcmp(argv[i], "--upload-file") == 0) {
            if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for %s", argv[i]); return -1; }
            if (c->upload_path != NULL) { set_cmdline_error(c, "Only one upload file is supported"); return -1; }
            c->upload_path = argv[++i];
            if (contains_crlf(c->upload_path)) {
                set_cmdline_error(c, "Invalid value for %s (newline detected)", argv[i - 1]); return -1;
            }
            continue;
        }
        if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--fail") == 0) { c->fail_on_http_error = true; continue; }
        if (strcmp(argv[i], "--progress-bar") == 0) { continue; }
        if (strcmp(argv[i], "-I") == 0 || strcmp(argv[i], "--head") == 0) {
            snprintf(c->request_method, sizeof(c->request_method), "HEAD"); c->method_explicit = true; continue;
        }
        if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--silent") == 0) { c->silent = true; continue; }
        if (strcmp(argv[i], "-S") == 0 || strcmp(argv[i], "--show-error") == 0) { c->show_error = true; continue; }
        if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for %s", argv[i]); return -1; }
            c->output_path = argv[++i];
            if (contains_crlf(c->output_path)) {
                set_cmdline_error(c, "Invalid value for %s (newline detected)", argv[i - 1]); return -1;
            }
            continue;
        }
        if (strcmp(argv[i], "-O") == 0 || strcmp(argv[i], "--remote-name") == 0) { c->output_remote_name = true; continue; }
        if (strcmp(argv[i], "-X") == 0 || strcmp(argv[i], "--request") == 0) {
            if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for %s", argv[i]); return -1; }
            i++;
            const char *method = argv[i];
            if (contains_crlf(method)) {
                set_cmdline_error(c, "Invalid HTTP method (newline detected)"); return -1;
            }
            if (strcasecmp(method, "GET") == 0) snprintf(c->request_method, sizeof(c->request_method), "GET");
            else if (strcasecmp(method, "POST") == 0) snprintf(c->request_method, sizeof(c->request_method), "POST");
            else if (strcasecmp(method, "PUT") == 0) snprintf(c->request_method, sizeof(c->request_method), "PUT");
            else if (strcasecmp(method, "DELETE") == 0) snprintf(c->request_method, sizeof(c->request_method), "DELETE");
            else if (strcasecmp(method, "PATCH") == 0) snprintf(c->request_method, sizeof(c->request_method), "PATCH");
            else if (strcasecmp(method, "OPTIONS") == 0) snprintf(c->request_method, sizeof(c->request_method), "OPTIONS");
            else {
                size_t mlen = strlen(method);
                if (mlen < sizeof(c->request_method))
                    memcpy(c->request_method, method, mlen + 1);
                else { set_cmdline_error(c, "Unknown or unsupported method: %s", method); return -1; }
            }
            c->method_explicit = true; continue;
        }
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--data") == 0 || strcmp(argv[i], "--data-binary") == 0) {
            if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for %s", argv[i]); free(c->request_data_alloc); return -1; }
            i++;
            if (argv[i][0] == '@') {
                const char *spec = argv[i] + 1;
                FILE *fp = NULL;
                bool close_fp = false;
                if (spec[0] == '-' && spec[1] == '\0') { fp = stdin; }
                else { fp = fopen(spec, "rb"); if (fp == NULL) { set_cmdline_error(c, "Unable to open data file '%s': %s", spec, strerror(errno)); return -1; } close_fp = true; }
                size_t total = 0;
                char *data = read_data_file(fp, &total);
                if (close_fp) fclose(fp);
                if (data == NULL) {
                    set_cmdline_error(c, "Failed to read data from '%s' (too large or out of memory)", spec);
                    return -1;
                }
                if (c->request_data != NULL) {
                    size_t old_len = c->request_data_len;
                    char *combined = malloc(old_len + 1 + total + 1);
                    if (combined == NULL) { free(data); set_cmdline_error(c, "Out of memory"); return -1; }
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
                if (contains_crlf(argv[i])) {
                    set_cmdline_error(c, "Invalid data value (newline detected)"); return -1;
                }
                if (c->request_data != NULL) {
                    size_t old_len = c->request_data_len;
                    size_t new_len = old_len + 1 + arg_len + 1;
                    char *combined = malloc(new_len);
                    if (combined == NULL) { set_cmdline_error(c, "Out of memory"); return -1; }
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
            if (c->address_family == AF_INET6) { set_cmdline_error(c, "-4 and -6 are mutually exclusive"); return -1; }
            c->address_family = AF_INET; continue;
        }
        if (strcmp(argv[i], "-6") == 0) {
            if (c->address_family == AF_INET) { set_cmdline_error(c, "-4 and -6 are mutually exclusive"); return -1; }
            c->address_family = AF_INET6; continue;
        }
        if (strcmp(argv[i], "--connect-timeout") == 0) {
            if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for --connect-timeout"); return -1; }
            int v = parse_nn(c, "--connect-timeout", argv[++i], "Invalid connect timeout");
            if (v < 0) return -1;
            c->connect_timeout_ms = v; continue;
        }
        if (strcmp(argv[i], "--read-timeout") == 0) {
            if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for --read-timeout"); return -1; }
            int v = parse_nn(c, "--read-timeout", argv[++i], "Invalid read timeout");
            if (v < 0) return -1;
            c->read_timeout_ms = v; continue;
        }
        if (strcmp(argv[i], "--max-time") == 0) {
            if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for --max-time"); return -1; }
            int v = parse_nn(c, "--max-time", argv[++i], "Invalid max time");
            if (v < 0) return -1;
            c->max_time_ms = v; continue;
        }
        if (strcmp(argv[i], "--max-redirs") == 0) {
            if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for --max-redirs"); return -1; }
            int v = parse_nn(c, "--max-redirs", argv[++i], "Invalid max redirects");
            if (v < 0) return -1;
            c->max_redirects = v; continue;
        }
        if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--cookie") == 0) {
            if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for %s", argv[i]); return -1; }
            i++;
            if (argv[i][0] == '@') { c->cookie_file_to_load = argv[i] + 1; }
            else {
                if (contains_crlf(argv[i])) {
                    set_cmdline_error(c, "Invalid cookie value (newline detected)"); return -1;
                }
                if (c->cookie_data != NULL) {
                    size_t new_len = strlen(c->cookie_data) + 2 + strlen(argv[i]) + 1;
                    char *combined = malloc(new_len);
                    if (combined == NULL) { set_cmdline_error(c, "Out of memory"); return -1; }
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
            if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for %s", argv[i]); return -1; }
            c->cookie_jar_path = argv[++i]; continue;
        }
        if (strcmp(argv[i], "--proxy") == 0) {
            if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for --proxy"); return -1; }
            c->proxy_url = argv[++i];
            if (contains_crlf(c->proxy_url)) {
                set_cmdline_error(c, "Invalid proxy URL (newline detected)"); return -1;
            }
            if (strncmp(c->proxy_url, "http://", 7) != 0 && strncmp(c->proxy_url, "https://", 8) != 0) {
                set_cmdline_error(c, "--proxy only supports http:// URLs"); return -1;
            }
            if (strncmp(c->proxy_url, "https://", 8) == 0) {
                set_cmdline_error(c, "--proxy does not support https:// proxy URLs (only http://)"); return -1;
            }
            continue;
        }
        if (strcmp(argv[i], "--resolve") == 0) {
            if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for --resolve"); return -1; }
            if (c->resolve_count >= MAX_RESOLVE_ENTRIES) { set_cmdline_error(c, "Too many --resolve entries (max %d)", MAX_RESOLVE_ENTRIES); return -1; }
            const char *val = argv[++i];
            const char *last_colon = strrchr(val, ':');
            if (last_colon == NULL || last_colon == val) {
                set_cmdline_error(c, "Invalid --resolve format (expected host:port:address)"); return -1;
            }
            const char *addr = last_colon + 1;
            size_t hostport_len = (size_t)(last_colon - val);
            char hostport[512];
            if (hostport_len >= sizeof(hostport)) { set_cmdline_error(c, "--resolve host:port too long"); return -1; }
            memcpy(hostport, val, hostport_len);
            hostport[hostport_len] = '\0';
            const char *port_colon = strrchr(hostport, ':');
            if (port_colon == NULL) {
                set_cmdline_error(c, "Invalid --resolve format (expected host:port:address)"); return -1;
            }
            *((char *)port_colon) = '\0';
            const char *host = hostport;
            const char *port = port_colon + 1;
            struct resolve_entry *re = &c->resolve_entries[c->resolve_count];
            memset(re, 0, sizeof(*re));
            if (strlen(host) >= sizeof(re->host) || strlen(port) >= sizeof(re->port)) {
                set_cmdline_error(c, "--resolve host or port too long"); return -1;
            }
            copy_bounded(re->host, sizeof(re->host), host);
            copy_bounded(re->port, sizeof(re->port), port);
            if (inet_pton(AF_INET, addr, &((struct sockaddr_in *)&re->ss)->sin_addr) == 1) {
                re->family = AF_INET;
                re->ss_len = sizeof(struct sockaddr_in);
                ((struct sockaddr_in *)&re->ss)->sin_family = AF_INET;
            } else if (inet_pton(AF_INET6, addr, &((struct sockaddr_in6 *)&re->ss)->sin6_addr) == 1) {
                re->family = AF_INET6;
                re->ss_len = sizeof(struct sockaddr_in6);
                ((struct sockaddr_in6 *)&re->ss)->sin6_family = AF_INET6;
            } else {
                set_cmdline_error(c, "Invalid address in --resolve: %s", addr); return -1;
            }
            c->resolve_count++;
            continue;
        }
        if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--referer") == 0) {
            if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for %s", argv[i]); return -1; }
            c->referer = argv[++i];
            if (contains_crlf(c->referer)) {
                set_cmdline_error(c, "Invalid value for %s (newline detected)", argv[i - 1]); return -1;
            }
            continue;
        }
        if (strcmp(argv[i], "--interface") == 0) {
            if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for --interface"); return -1; }
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
            if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for --retry"); return -1; }
            int v = parse_nn(c, "--retry", argv[++i], "Invalid retry count");
            if (v < 0) return -1;
            c->retry_count = v; continue;
        }
        if (strcmp(argv[i], "--retry-delay") == 0) {
            if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for --retry-delay"); return -1; }
            int v = parse_nn(c, "--retry-delay", argv[++i], "Invalid retry delay");
            if (v < 0) return -1;
            c->retry_delay_ms = v * 1000; continue;
        }
        if (strcmp(argv[i], "--cacert") == 0) {
            if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for --cacert"); return -1; }
            c->cacert = argv[++i]; continue;
        }
        if (strcmp(argv[i], "--capath") == 0) {
            if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for --capath"); return -1; }
            c->capath = argv[++i]; continue;
        }
        if (strcmp(argv[i], "--compressed") == 0) { c->compressed = true; continue; }
        if (strcmp(argv[i], "--data-urlencode") == 0) {
            if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for --data-urlencode"); return -1; }
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
                if (fp == NULL) { set_cmdline_error(c, "Cannot open '%s' for --data-urlencode", fpath); return -1; }
                size_t total = 0;
                file_buf = read_data_file(fp, &total);
                if (fp != stdin) fclose(fp);
                if (file_buf == NULL) {
                    set_cmdline_error(c, "Failed to read '%s' (too large or out of memory)", fpath);
                    return -1;
                }
                content = file_buf;
            } else if (arg[0] == '=') {
                content = arg + 1;
            } else {
                const char *at = strchr(arg, '@');
                const char *eq = strchr(arg, '=');
                if (eq != NULL && (at == NULL || eq < at)) {
                    size_t nlen = (size_t)(eq - arg);
                    char *n = malloc(nlen + 1);
                    if (n == NULL) { set_cmdline_error(c, "Out of memory"); return -1; }
                    memcpy(n, arg, nlen); n[nlen] = '\0';
                    name = n;
                    content = eq + 1;
                } else if (at != NULL) {
                    size_t nlen = (size_t)(at - arg);
                    if (nlen > 0) {
                        char *n = malloc(nlen + 1);
                        if (n == NULL) { set_cmdline_error(c, "Out of memory"); return -1; }
                        memcpy(n, arg, nlen); n[nlen] = '\0';
                        name = n;
                    }
                    const char *fpath = at + 1;
                    FILE *fp = NULL;
                    if (fpath[0] == '-' && fpath[1] == '\0') fp = stdin;
                    else fp = fopen(fpath, "rb");
                    if (fp == NULL) { set_cmdline_error(c, "Cannot open '%s' for --data-urlencode", fpath); return -1; }
                    size_t total = 0;
                    file_buf = read_data_file(fp, &total);
                    if (fp != stdin) fclose(fp);
                    if (file_buf == NULL) {
                        set_cmdline_error(c, "Failed to read '%s' (too large or out of memory)", fpath);
                        return -1;
                    }
                    content = file_buf;
                } else {
                    content = arg;
                }
            }
            size_t clen = strlen(content);
            size_t max_encoded = clen * 3 + 1;
            encoded = malloc(max_encoded);
            if (encoded == NULL) { set_cmdline_error(c, "Out of memory"); free(file_buf); return -1; }
            if (url_encode(content, encoded, max_encoded) != 0) {
                set_cmdline_error(c, "URL-encoding failed"); free(encoded); free(file_buf); return -1;
            }
            size_t name_len = (name != NULL) ? strlen(name) : 0;
            size_t need = name_len + 1 + strlen(encoded) + 1;
            char *final = malloc(need);
            if (final == NULL) { set_cmdline_error(c, "Out of memory"); free(encoded); free(file_buf); return -1; }
            if (name != NULL)
                snprintf(final, need, "%s=%s", name, encoded);
            else
                snprintf(final, need, "%s", encoded);
            free(encoded);
            free(file_buf);
            if (c->request_data != NULL) {
                size_t new_len = strlen(c->request_data) + 1 + strlen(final) + 1;
                char *combined = malloc(new_len);
                if (combined == NULL) { set_cmdline_error(c, "Out of memory"); free(final); return -1; }
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
            if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for %s", argv[i]); return -1; }
            c->write_out_format = argv[++i]; continue;
        }
        if (strcmp(argv[i], "--unix-socket") == 0) {
            if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for --unix-socket"); return -1; }
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
                    case 'I': snprintf(c->request_method, sizeof(c->request_method), "HEAD"); c->method_explicit = true; break;
                    case 'h': print_help(argv[0]); return 1;
                    case 'o':
                        if (argv[i][j + 1] != '\0') {
                            c->output_path = argv[i] + j + 1;
                            if (contains_crlf(c->output_path)) {
                                set_cmdline_error(c, "Invalid value for -o (newline detected)"); return -1;
                            }
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

        if (argv[i][0] == '-') { set_cmdline_error(c, "Unknown option: %s", argv[i]); return -1; }

        const char **new_urls = realloc(c->urls, (c->url_count + 1) * sizeof(*c->urls));
        if (new_urls == NULL) { set_cmdline_error(c, "Out of memory"); return -1; }
        c->urls = new_urls;
        c->urls[c->url_count++] = argv[i];
        if (c->input_url == NULL) c->input_url = argv[i];
        if (c->compare_urls_mode && c->compare_url == NULL && c->url_count >= 2)
            c->compare_url = argv[i];
    }
    return 0;
}
