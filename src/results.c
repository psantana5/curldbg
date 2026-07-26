#include "curldbg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>

int final_status_code(const struct run_result *result) {
    return (result->hop_count <= 0) ? 0 : result->hops[result->hop_count - 1].status_code;
}

void final_endpoint(const struct run_result *result, char *out, size_t out_size) {
    if (result->hop_count <= 0) { snprintf(out, out_size, "n/a"); return; }
    const struct hop_info *hop = &result->hops[result->hop_count - 1];
    snprintf(out, out_size, "%s (%s)", hop->connected_ip, family_name(hop->connected_family));
}

bool is_loopback_ip(const char *ip) {
    return ip != NULL && (strcmp(ip, "127.0.0.1") == 0 || strcmp(ip, "::1") == 0);
}

const char *family_short_name(int family) {
    if (family == AF_INET) return "v4";
    if (family == AF_INET6) return "v6";
    return "?";
}

void print_single_output(const struct run_result *result) {
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

void print_compare_metric_row(const char *metric, double a, double b) {
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

void print_compare_text_row(const char *metric, const char *a, const char *b) {
    printf("%-10s | %-24s | %-24s | %-20s\n", metric, a, b, (strcmp(a, b) == 0) ? "same" : "different");
}

void print_compare_family_metric(const char *label, double v4, double v6) {
    double delta = v6 - v4;
    if (v4 < 0.0 || v6 < 0.0) { printf("  %-14s n/a\n", label); return; }
    if (v4 > 0.0)
        printf("  %-14s %+8.2f ms (%+.1f%%)\n", label, delta, (delta / v4) * 100.0);
    else
        printf("  %-14s %+8.2f ms\n", label, delta);
}

void print_compare_family_run(const char *name, const struct run_result *result, bool ok) {
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
