#include "curldbg.h"
#include "flags.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <openssl/tls1.h>

#define MAX_DATA_FILE_SIZE (16 * 1024 * 1024)

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

static int validate_no_crlf(const char *value, const char *flag_name, struct cmdline_opts *c) {
    if (contains_crlf(value)) {
        set_cmdline_error(c, "Invalid value for %s (newline detected)", flag_name);
        return -1;
    }
    return 0;
}

static int handle_int_flag(struct cmdline_opts *c, const char *flag_name,
                           const char *value, const char *desc, int *target) {
    int v = parse_nn(c, flag_name, value, desc);
    if (v < 0) return -1;
    *target = v;
    return 0;
}

static int add_extra_header(struct cmdline_opts *c, const char *value) {
    const char **next = realloc(c->extra_headers, (c->extra_header_count + 1) * sizeof(*c->extra_headers));
    if (next == NULL) { set_cmdline_error(c, "Out of memory"); return -1; }
    c->extra_headers = next;
    c->extra_headers[c->extra_header_count++] = value;
    return 0;
}

static int append_data(struct cmdline_opts *c, const char *data, size_t data_len, bool alloced) {
    if (c->request_data != NULL) {
        size_t old_len = c->request_data_len;
        size_t new_len = old_len + 1 + data_len + 1;
        char *combined = malloc(new_len);
        if (combined == NULL) { set_cmdline_error(c, "Out of memory"); return -1; }
        memcpy(combined, c->request_data, old_len);
        combined[old_len] = '&';
        memcpy(combined + old_len + 1, data, data_len);
        combined[old_len + 1 + data_len] = '\0';
        free(c->request_data_alloc);
        c->request_data = combined;
        c->request_data_alloc = combined;
        c->request_data_len = old_len + 1 + data_len;
        c->request_data_urlencode_alloc = NULL;
        if (alloced) free((void *)data);
    } else {
        free(c->request_data_alloc);
        if (alloced) {
            c->request_data = data;
            c->request_data_alloc = (char *)data;
        } else {
            c->request_data = data;
            c->request_data_alloc = NULL;
        }
        c->request_data_len = data_len;
        c->request_data_urlencode_alloc = NULL;
    }
    return 0;
}

static int handle_data_arg(struct cmdline_opts *c, const char *arg) {
    if (arg[0] == '@') {
        const char *spec = arg + 1;
        FILE *fp = NULL;
        bool close_fp = false;
        if (spec[0] == '-' && spec[1] == '\0') { fp = stdin; }
        else { fp = fopen(spec, "rb"); if (fp == NULL) { set_cmdline_error(c, "Unable to open data file '%s': %s", spec, strerror(errno)); return -1; } close_fp = true; }
        size_t total = 0;
        const char *data = read_data_file(fp, &total);
        if (close_fp) fclose(fp);
        if (data == NULL) {
            set_cmdline_error(c, "Failed to read data from '%s' (too large or out of memory)", spec);
            return -1;
        }
        return append_data(c, data, total, true);
    }

    if (validate_no_crlf(arg, "--data", c) != 0) return -1;
    return append_data(c, arg, strlen(arg), false);
}

static int handle_data_urlencode(struct cmdline_opts *c, const char *arg) {
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
    int rc = append_data(c, final, strlen(final), true);
    if (rc != 0) free(final);
    free((void *)name);
    return rc;
}

static const struct flag_info *find_flag(const char *name) {
    for (int i = 0; g_flags[i].desc != NULL; i++) {
        if ((g_flags[i].short_name && strcmp(g_flags[i].short_name, name) == 0) ||
            (g_flags[i].long_name && strcmp(g_flags[i].long_name, name) == 0))
            return &g_flags[i];
    }
    return NULL;
}

static int handle_flag(enum flag_id id, const char *value, struct cmdline_opts *c, int *exit_code) {
    *exit_code = 0;
    switch (id) {
        case FLAG_REQUEST:
            if (value == NULL) { set_cmdline_error(c, "Missing value for --request"); return -1; }
            if (validate_no_crlf(value, "--request", c) != 0) return -1;
            if (strcasecmp(value, "GET") == 0) snprintf(c->request_method, sizeof(c->request_method), "GET");
            else if (strcasecmp(value, "POST") == 0) snprintf(c->request_method, sizeof(c->request_method), "POST");
            else if (strcasecmp(value, "PUT") == 0) snprintf(c->request_method, sizeof(c->request_method), "PUT");
            else if (strcasecmp(value, "DELETE") == 0) snprintf(c->request_method, sizeof(c->request_method), "DELETE");
            else if (strcasecmp(value, "PATCH") == 0) snprintf(c->request_method, sizeof(c->request_method), "PATCH");
            else if (strcasecmp(value, "OPTIONS") == 0) snprintf(c->request_method, sizeof(c->request_method), "OPTIONS");
            else {
                size_t mlen = strlen(value);
                if (mlen < sizeof(c->request_method))
                    memcpy(c->request_method, value, mlen + 1);
                else { set_cmdline_error(c, "Unknown or unsupported method: %s", value); return -1; }
            }
            c->method_explicit = true;
            return 0;

        case FLAG_HEADER:
            if (value == NULL) { set_cmdline_error(c, "Missing value for --header"); return -1; }
            if (contains_crlf(value)) {
                set_cmdline_error(c, "Invalid header value (newline detected)"); return -1;
            }
            return add_extra_header(c, value);

        case FLAG_DATA:
        case FLAG_DATA_BINARY:
            if (value == NULL) { set_cmdline_error(c, "Missing value for --data"); return -1; }
            return handle_data_arg(c, value);

        case FLAG_DATA_URLENCODE:
            if (value == NULL) { set_cmdline_error(c, "Missing value for --data-urlencode"); return -1; }
            return handle_data_urlencode(c, value);

        case FLAG_UPLOAD_FILE:
            if (value == NULL) { set_cmdline_error(c, "Missing value for --upload-file"); return -1; }
            if (c->upload_path != NULL) { set_cmdline_error(c, "Only one upload file is supported"); return -1; }
            if (validate_no_crlf(value, "--upload-file", c) != 0) return -1;
            c->upload_path = value;
            return 0;

        case FLAG_USER:
            if (value == NULL) { set_cmdline_error(c, "Missing value for --user"); return -1; }
            if (validate_no_crlf(value, "--user", c) != 0) return -1;
            c->basic_auth = value;
            return 0;

        case FLAG_USER_AGENT:
            if (value == NULL) { set_cmdline_error(c, "Missing value for --user-agent"); return -1; }
            if (validate_no_crlf(value, "--user-agent", c) != 0) return -1;
            c->user_agent = value;
            return 0;

        case FLAG_REFERER:
            if (value == NULL) { set_cmdline_error(c, "Missing value for --referer"); return -1; }
            if (validate_no_crlf(value, "--referer", c) != 0) return -1;
            c->referer = value;
            return 0;

        case FLAG_COOKIE:
            if (value == NULL) { set_cmdline_error(c, "Missing value for --cookie"); return -1; }
            if (value[0] == '@') { c->cookie_file_to_load = value + 1; }
            else {
                if (validate_no_crlf(value, "--cookie", c) != 0) return -1;
                if (c->cookie_data != NULL) {
                    size_t new_len = strlen(c->cookie_data) + 2 + strlen(value) + 1;
                    char *combined = malloc(new_len);
                    if (combined == NULL) { set_cmdline_error(c, "Out of memory"); return -1; }
                    snprintf(combined, new_len, "%s; %s", c->cookie_data, value);
                    free(c->cookie_data_alloc);
                    c->cookie_data = combined; c->cookie_data_alloc = combined;
                } else {
                    c->cookie_data = value;
                }
            }
            return 0;

        case FLAG_COOKIE_JAR:
            if (value == NULL) { set_cmdline_error(c, "Missing value for --cookie-jar"); return -1; }
            c->cookie_jar_path = value;
            return 0;

        case FLAG_PROXY:
            if (value == NULL) { set_cmdline_error(c, "Missing value for --proxy"); return -1; }
            if (validate_no_crlf(value, "--proxy", c) != 0) return -1;
            if (strncmp(value, "http://", 7) != 0 && strncmp(value, "https://", 8) != 0) {
                set_cmdline_error(c, "--proxy only supports http:// URLs"); return -1;
            }
            if (strncmp(value, "https://", 8) == 0) {
                set_cmdline_error(c, "--proxy does not support https:// proxy URLs (only http://)"); return -1;
            }
            c->proxy_url = value;
            return 0;

        case FLAG_RESOLVE:
            if (value == NULL) { set_cmdline_error(c, "Missing value for --resolve"); return -1; }
            if (c->resolve_count >= MAX_RESOLVE_ENTRIES) { set_cmdline_error(c, "Too many --resolve entries (max %d)", MAX_RESOLVE_ENTRIES); return -1; }
            {
                const char *host_start = value;
                const char *host_end;
                if (host_start[0] == '[') {
                    host_end = strchr(host_start, ']');
                    if (host_end == NULL) { set_cmdline_error(c, "Unclosed bracket in --resolve host"); return -1; }
                    host_end++;
                    if (*host_end != ':') { set_cmdline_error(c, "Expected ':' after bracketed host in --resolve"); return -1; }
                } else {
                    host_end = strchr(host_start, ':');
                    if (host_end == NULL || host_end == host_start) {
                        set_cmdline_error(c, "Invalid --resolve format (expected host:port:address)"); return -1;
                    }
                }
                const char *port_start = host_end + 1;
                const char *port_end = strchr(port_start, ':');
                if (port_end == NULL || port_end == port_start) {
                    set_cmdline_error(c, "Invalid --resolve format (expected host:port:address)"); return -1;
                }
                const char *addr = port_end + 1;
                if (*addr == '\0') {
                    set_cmdline_error(c, "Missing address in --resolve"); return -1;
                }
                struct resolve_entry *re = &c->resolve_entries[c->resolve_count];
                memset(re, 0, sizeof(*re));
                size_t hlen, plen;
                if (host_start[0] == '[') {
                    hlen = (size_t)(host_end - host_start - 2);
                    if (hlen == 0 || hlen >= sizeof(re->host)) {
                        set_cmdline_error(c, "--resolve host too long or empty"); return -1;
                    }
                    memcpy(re->host, host_start + 1, hlen);
                } else {
                    hlen = (size_t)(host_end - host_start);
                    if (hlen >= sizeof(re->host)) {
                        set_cmdline_error(c, "--resolve host too long"); return -1;
                    }
                    memcpy(re->host, host_start, hlen);
                }
                re->host[hlen] = '\0';
                plen = (size_t)(port_end - port_start);
                if (plen >= sizeof(re->port)) {
                    set_cmdline_error(c, "--resolve port too long"); return -1;
                }
                memcpy(re->port, port_start, plen);
                re->port[plen] = '\0';
                const char *resolve_addr = addr;
                char addr_buf[64];
                if (addr[0] == '[') {
                    const char *close_bracket = strchr(addr, ']');
                    if (close_bracket == NULL || *(close_bracket + 1) != '\0') {
                        set_cmdline_error(c, "Invalid bracketed address in --resolve (expected [addr])"); return -1;
                    }
                    size_t a_len = (size_t)(close_bracket - addr - 1);
                    if (a_len == 0 || a_len >= sizeof(addr_buf)) {
                        set_cmdline_error(c, "Invalid --resolve IPv6 address"); return -1;
                    }
                    memcpy(addr_buf, addr + 1, a_len);
                    addr_buf[a_len] = '\0';
                    resolve_addr = addr_buf;
                }
                if (inet_pton(AF_INET, resolve_addr, &((struct sockaddr_in *)&re->ss)->sin_addr) == 1) {
                    re->family = AF_INET;
                    re->ss_len = sizeof(struct sockaddr_in);
                    ((struct sockaddr_in *)&re->ss)->sin_family = AF_INET;
                } else if (inet_pton(AF_INET6, resolve_addr, &((struct sockaddr_in6 *)&re->ss)->sin6_addr) == 1) {
                    re->family = AF_INET6;
                    re->ss_len = sizeof(struct sockaddr_in6);
                    ((struct sockaddr_in6 *)&re->ss)->sin6_family = AF_INET6;
                } else {
                    set_cmdline_error(c, "Invalid address in --resolve: %s", addr); return -1;
                }
                c->resolve_count++;
            }
            return 0;

        case FLAG_OUTPUT:
            if (value == NULL) { set_cmdline_error(c, "Missing value for --output"); return -1; }
            if (validate_no_crlf(value, "--output", c) != 0) return -1;
            c->output_path = value;
            return 0;

        case FLAG_REMOTE_NAME:
            c->output_remote_name = true;
            return 0;

        case FLAG_WRITE_OUT:
            if (value == NULL) { set_cmdline_error(c, "Missing value for --write-out"); return -1; }
            c->write_out_format = value;
            return 0;

        case FLAG_SILENT:
            c->silent = true;
            return 0;

        case FLAG_SHOW_ERROR:
            c->show_error = true;
            return 0;

        case FLAG_VERBOSE:
            c->verbose = true;
            return 0;

        case FLAG_HEAD:
            snprintf(c->request_method, sizeof(c->request_method), "HEAD");
            c->method_explicit = true;
            return 0;

        case FLAG_LOCATION:
            c->follow_redirects = true;
            return 0;

        case FLAG_MAX_REDIRS:
            if (value == NULL) { set_cmdline_error(c, "Missing value for --max-redirs"); return -1; }
            return handle_int_flag(c, "--max-redirs", value, "Invalid max redirects", &c->max_redirects);

        case FLAG_FAIL:
            c->fail_on_http_error = true;
            return 0;

        case FLAG_IPV4:
            if (c->address_family == AF_INET6) { set_cmdline_error(c, "-4 and -6 are mutually exclusive"); return -1; }
            c->address_family = AF_INET;
            return 0;

        case FLAG_IPV6:
            if (c->address_family == AF_INET) { set_cmdline_error(c, "-4 and -6 are mutually exclusive"); return -1; }
            c->address_family = AF_INET6;
            return 0;

        case FLAG_CONNECT_TIMEOUT:
            if (value == NULL) { set_cmdline_error(c, "Missing value for --connect-timeout"); return -1; }
            return handle_int_flag(c, "--connect-timeout", value, "Invalid connect timeout", &c->connect_timeout_ms);

        case FLAG_READ_TIMEOUT:
            if (value == NULL) { set_cmdline_error(c, "Missing value for --read-timeout"); return -1; }
            return handle_int_flag(c, "--read-timeout", value, "Invalid read timeout", &c->read_timeout_ms);

        case FLAG_MAX_TIME:
            if (value == NULL) { set_cmdline_error(c, "Missing value for --max-time"); return -1; }
            return handle_int_flag(c, "--max-time", value, "Invalid max time", &c->max_time_ms);

        case FLAG_RETRY:
            if (value == NULL) { set_cmdline_error(c, "Missing value for --retry"); return -1; }
            return handle_int_flag(c, "--retry", value, "Invalid retry count", &c->retry_count);

        case FLAG_RETRY_DELAY:
            if (value == NULL) { set_cmdline_error(c, "Missing value for --retry-delay"); return -1; }
            { int v = parse_nn(c, "--retry-delay", value, "Invalid retry delay");
              if (v < 0) return -1;
              c->retry_delay_ms = v * 1000; }
            return 0;

        case FLAG_NO_HAPPY_EYEBALLS:
            c->happy_eyeballs = false;
            return 0;

        case FLAG_HTTP1_1:
            c->force_http_version = 1;
            return 0;

        case FLAG_HTTP2:
            c->force_http_version = 2;
            return 0;

        case FLAG_INTERFACE:
            if (value == NULL) { set_cmdline_error(c, "Missing value for --interface"); return -1; }
            c->bind_interface = value;
            return 0;

        case FLAG_UNIX_SOCKET:
            if (value == NULL) { set_cmdline_error(c, "Missing value for --unix-socket"); return -1; }
            c->unix_socket_path = value;
            return 0;

        case FLAG_INSECURE:
            c->insecure_tls = true;
            return 0;

        case FLAG_CACERT:
            if (value == NULL) { set_cmdline_error(c, "Missing value for --cacert"); return -1; }
            c->cacert = value;
            return 0;

        case FLAG_CAPATH:
            if (value == NULL) { set_cmdline_error(c, "Missing value for --capath"); return -1; }
            c->capath = value;
            return 0;

        case FLAG_TLSV1_2:
            c->tls_min_version = TLS1_2_VERSION;
            c->tls_max_version = TLS1_2_VERSION;
            return 0;

        case FLAG_TLSV1_3:
            c->tls_min_version = TLS1_3_VERSION;
            c->tls_max_version = TLS1_3_VERSION;
            return 0;

        case FLAG_COMPRESSED:
            c->compressed = true;
            return 0;

        case FLAG_COMPARE:
            c->compare_family_mode = true;
            return 0;

        case FLAG_COMPARE_URLS:
            c->compare_urls_mode = true;
            return 0;

        case FLAG_HELP:
            print_help("curldbg");
            *exit_code = 1;
            return 1;

        case FLAG_VERSION:
            printf("curldbg %s\n", CURLDBG_VERSION);
            printf("Author: Pau Santana\n");
            *exit_code = 1;
            return 1;

        case FLAG_PROGRESS_BAR:
            return 0;

        case FLAG_DISABLE:
            return 0;

        case FLAG_NONE:
            break;
    }
    set_cmdline_error(c, "Unknown option");
    return -1;
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
                size_t new_url_count = (size_t)c->url_count + 1;
                const char **new_urls = realloc(c->urls, new_url_count * sizeof(*c->urls));
                if (new_urls == NULL) { set_cmdline_error(c, "Out of memory"); return -1; }
                c->urls = new_urls;
                c->urls[c->url_count++] = argv[i];
                if (c->input_url == NULL) c->input_url = argv[i];
                if (c->compare_urls_mode && c->compare_url == NULL && c->url_count >= 2)
                    c->compare_url = argv[i];
            }
            break;
        }

        const struct flag_info *f = find_flag(argv[i]);
        if (f != NULL) {
            const char *value = NULL;
            if (f->arg != NULL) {
                if (i + 1 >= argc) { set_cmdline_error(c, "Missing value for %s", argv[i]); return -1; }
                value = argv[++i];
            }
            int exit_code = 0;
            int rc = handle_flag(f->id, value, c, &exit_code);
            if (rc == 1) return exit_code;
            if (rc < 0) return -1;
            continue;
        }

        if (argv[i][0] == '-' && argv[i][1] != '\0' && argv[i][1] != '-' && argv[i][2] != '\0') {
            bool handled = true;
            const char *flag_str = argv[i];
            for (size_t j = 1; flag_str[j] != '\0'; j++) {
                switch (flag_str[j]) {
                    case 'f': c->fail_on_http_error = true; break;
                    case 's': c->silent = true; break;
                    case 'S': c->show_error = true; break;
                    case 'v': c->verbose = true; break;
                    case 'k': c->insecure_tls = true; break;
                    case 'L': c->follow_redirects = true; break;
                    case 'O': c->output_remote_name = true; break;
                    case 'I': snprintf(c->request_method, sizeof(c->request_method), "HEAD"); c->method_explicit = true; break;
                    case 'h': print_help(argv[0]); return 1;
                    case 'H':
                        if (flag_str[j + 1] != '\0') {
                            const char *hv = flag_str + j + 1;
                            if (contains_crlf(hv)) {
                                set_cmdline_error(c, "Invalid header value (newline detected)"); return -1;
                            }
                            if (add_extra_header(c, hv) != 0) return -1;
                            while (flag_str[j + 1] != '\0') j++;
                        } else if (i + 1 < argc) {
                            i++;
                            const char *hv = argv[i];
                            if (contains_crlf(hv)) {
                                set_cmdline_error(c, "Invalid header value (newline detected)"); return -1;
                            }
                            if (add_extra_header(c, hv) != 0) return -1;
                        } else {
                            handled = false;
                        }
                        break;
                    case 'o':
                        if (flag_str[j + 1] != '\0') {
                            c->output_path = flag_str + j + 1;
                            if (validate_no_crlf(c->output_path, "-o", c) != 0) return -1;
                            while (flag_str[j + 1] != '\0') j++;
                        } else if (i + 1 < argc) {
                            i++;
                            c->output_path = argv[i];
                            if (validate_no_crlf(c->output_path, "-o", c) != 0) return -1;
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

        size_t new_url_count = (size_t)c->url_count + 1;
        const char **new_urls = realloc(c->urls, new_url_count * sizeof(*c->urls));
        if (new_urls == NULL) { set_cmdline_error(c, "Out of memory"); return -1; }
        c->urls = new_urls;
        c->urls[c->url_count++] = argv[i];
        if (c->input_url == NULL) c->input_url = argv[i];
        if (c->compare_urls_mode && c->compare_url == NULL && c->url_count >= 2)
            c->compare_url = argv[i];
    }
    return 0;
}

int validate_cmdline_opts(struct cmdline_opts *c) {
    if (c->compare_family_mode && c->compare_urls_mode) {
        set_cmdline_error(c, "--compare and --compare-urls are mutually exclusive");
        return -1;
    }
    if (c->output_path != NULL && c->output_remote_name) {
        set_cmdline_error(c, "-o and -O are mutually exclusive");
        return -1;
    }
    if ((c->output_path != NULL || c->output_remote_name) && (c->compare_family_mode || c->compare_urls_mode)) {
        set_cmdline_error(c, "-o/-O are only supported in single request mode");
        return -1;
    }
    if (c->upload_path != NULL && (c->compare_family_mode || c->compare_urls_mode)) {
        set_cmdline_error(c, "-T/--upload-file is only supported in single request mode");
        return -1;
    }
    if (c->upload_path != NULL && c->request_data != NULL) {
        set_cmdline_error(c, "-T/--upload-file cannot be combined with -d/--data");
        return -1;
    }
    if (c->basic_auth != NULL && strchr(c->basic_auth, ':') == NULL) {
        set_cmdline_error(c, "-u/--user must be in the form user:password");
        return -1;
    }
    if (c->upload_path != NULL) {
        if (c->method_explicit && strcasecmp(c->request_method, "PUT") != 0) {
            set_cmdline_error(c, "-T/--upload-file requires -X PUT or no -X flag");
            return -1;
        }
        if (!c->method_explicit) safe_strlcpy(c->request_method, "PUT", sizeof(c->request_method));
    }
    if (c->request_data != NULL && !c->method_explicit)
        safe_strlcpy(c->request_method, "POST", sizeof(c->request_method));
    return 0;
}
