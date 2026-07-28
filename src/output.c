#include "curldbg.h"

#include <stdio.h>
#include <string.h>

void write_out_expand(const char *fmt, const struct run_result *result) {
    while (*fmt != '\0') {
        if (fmt[0] == '%' && fmt[1] == '%') {
            putchar('%');
            fmt += 2;
            continue;
        }
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
                } else if (strcmp(varname, "http_version") == 0) {
                    printf("%s", result->resp.http_version[0] != '\0'
                           ? result->resp.http_version : "HTTP/1.1");
                } else if (strcmp(varname, "redirect_url") == 0) {
                    if (result->hop_count > 0) {
                        const struct hop_info *h = &result->hops[result->hop_count - 1];
                        if (h->has_redirect_target)
                            printf("%s", h->redirect_url);
                    }
                } else {
                    /* unknown variable: curl prints nothing */
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
