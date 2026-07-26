#include "curldbg.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <arpa/inet.h>

static void copy_string(char *dest, size_t dest_size, const char *src) {
    if (dest_size == 0) return;
    size_t n = strlen(src);
    if (n >= dest_size) n = dest_size - 1;
    memcpy(dest, src, n);
    dest[n] = '\0';
}

static bool is_ip_address(const char *s) {
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, s, &a4) == 1) return true;
    if (inet_pton(AF_INET6, s, &a6) == 1) return true;
    return false;
}

#include <libpsl.h>

static bool cookie_domain_matches(const char *host, const char *domain, bool include_subdomains) {
    if (domain == NULL || domain[0] == '\0' || host == NULL || host[0] == '\0') return false;
    if (is_ip_address(domain)) return strcmp(host, domain) == 0;

    const psl_ctx_t *psl = psl_builtin();
    if (psl == NULL) return false;

    const char *d = domain;
    while (*d == '.') d++;
    if (psl_registrable_domain(psl, d) == NULL) return false;

    size_t host_len = strlen(host);
    size_t dom_len = strlen(d);
    if (dom_len > host_len) return false;

    if (include_subdomains) {
        if (dom_len == host_len)
            return strcasecmp(host, d) == 0;
        if (host[host_len - dom_len - 1] != '.')
            return false;
        return strcasecmp(host + host_len - dom_len, d) == 0;
    }
    return host_len == dom_len && strcasecmp(host, d) == 0;
}

void cookie_jar_init(struct cookie_jar *jar) {
    if (jar == NULL) return;
    memset(jar, 0, sizeof(*jar));
}

void cookie_jar_add_set_cookie(struct cookie_jar *jar, const char *set_cookie, const char *request_host) {
    if (jar->count >= MAX_COOKIES || set_cookie == NULL || *set_cookie == '\0' || request_host == NULL) return;

    struct cookie_entry *entry = &jar->entries[jar->count];
    memset(entry, 0, sizeof(*entry));

    copy_string(entry->domain, sizeof(entry->domain), request_host);
    snprintf(entry->path, sizeof(entry->path), "/");

    const char *eq = strchr(set_cookie, '=');
    const char *semi = strchr(set_cookie, ';');
    if (eq == NULL || (semi != NULL && eq > semi)) return;

    size_t name_len = (size_t)(eq - set_cookie);
    if (name_len >= sizeof(entry->name)) name_len = sizeof(entry->name) - 1;
    memcpy(entry->name, set_cookie, name_len);
    entry->name[name_len] = '\0';

    if (semi == NULL) {
        size_t val_len = strlen(eq + 1);
        if (val_len >= sizeof(entry->value)) val_len = sizeof(entry->value) - 1;
        memcpy(entry->value, eq + 1, val_len);
        entry->value[val_len] = '\0';
        if (!cookie_domain_matches(request_host, entry->domain, entry->include_subdomains))
            return;
        jar->count++;
        return;
    }

    {
        size_t val_len = (size_t)(semi - eq - 1);
        if (val_len >= sizeof(entry->value)) val_len = sizeof(entry->value) - 1;
        memcpy(entry->value, eq + 1, val_len);
        entry->value[val_len] = '\0';
    }

    const char *p = semi + 1;
    while (*p != '\0') {
        while (*p == ' ' || *p == '\t') p++;
        const char *attr_end = strchr(p, ';');
        size_t attr_len = (attr_end != NULL) ? (size_t)(attr_end - p) : strlen(p);

        char attr_buf[512];
        size_t cplen = attr_len;
        if (cplen >= sizeof(attr_buf)) cplen = sizeof(attr_buf) - 1;
        memcpy(attr_buf, p, cplen);
        attr_buf[cplen] = '\0';

        if (strncasecmp(attr_buf, "domain=", 7) == 0) {
            const char *d = attr_buf + 7;
            while (*d == ' ') d++;
            if (*d == '.') d++;
            size_t dlen = strlen(d);
            if (dlen >= sizeof(entry->domain)) dlen = sizeof(entry->domain) - 1;
            memcpy(entry->domain, d, dlen);
            entry->domain[dlen] = '\0';
            entry->include_subdomains = true;
        } else if (strncasecmp(attr_buf, "path=", 5) == 0) {
            const char *pa = attr_buf + 5;
            while (*pa == ' ') pa++;
            size_t palen = strlen(pa);
            if (palen >= sizeof(entry->path)) palen = sizeof(entry->path) - 1;
            memcpy(entry->path, pa, palen);
            entry->path[palen] = '\0';
        } else if (strcasecmp(attr_buf, "secure") == 0) {
            entry->secure = true;
        } else if (strcasecmp(attr_buf, "httponly") == 0) {
            entry->httponly = true;
        } else if (strncasecmp(attr_buf, "samesite=", 9) == 0) {
            const char *v = attr_buf + 9;
            while (*v == ' ') v++;
            if (strcasecmp(v, "strict") == 0) snprintf(entry->samesite, sizeof(entry->samesite), "Strict");
            else if (strcasecmp(v, "lax") == 0) snprintf(entry->samesite, sizeof(entry->samesite), "Lax");
            else if (strcasecmp(v, "none") == 0) snprintf(entry->samesite, sizeof(entry->samesite), "None");
        }

        if (attr_end == NULL) break;
        p = attr_end + 1;
    }

    if (!cookie_domain_matches(request_host, entry->domain, entry->include_subdomains))
        return;

    jar->count++;
}

void cookie_jar_get_header(struct cookie_jar *jar, const char *host, const char *path,
                           bool secure_connection, char *out, size_t out_size) {
    out[0] = '\0';
    size_t offset = 0;
    size_t path_len = strlen(path);

    for (int i = 0; i < jar->count; i++) {
        const struct cookie_entry *e = &jar->entries[i];

        if (e->secure && !secure_connection) continue;
        if (!cookie_domain_matches(host, e->domain, e->include_subdomains)) continue;

        size_t e_path_len = strlen(e->path);
        if (path_len < e_path_len || strncmp(path, e->path, e_path_len) != 0) continue;

        if (offset > 0) {
            if (offset + 2 >= out_size) break;
            out[offset++] = ';';
            out[offset++] = ' ';
        }
        int n = snprintf(out + offset, out_size - offset, "%s=%s", e->name, e->value);
        if (n < 0 || (size_t)n >= out_size - offset) break;
        offset += (size_t)n;
    }
}

int cookie_jar_save(const struct cookie_jar *jar, const char *filepath) {
    FILE *f = fopen(filepath, "w");
    if (f == NULL) return -1;

    fprintf(f, "# Netscape HTTP Cookie File\n");
    fprintf(f, "# Generated by curldbg\n\n");

    for (int i = 0; i < jar->count; i++) {
        const struct cookie_entry *e = &jar->entries[i];
        fprintf(f, "%s\t%s\t%s\t%s\t0\t%s\t%s\n",
                e->domain,
                e->include_subdomains ? "TRUE" : "FALSE",
                e->path,
                e->secure ? "TRUE" : "FALSE",
                e->name,
                e->value);
    }

    fclose(f);
    return 0;
}

void cookie_jar_load(struct cookie_jar *jar, const char *filepath) {
    if (jar == NULL || filepath == NULL) return;
    FILE *f = fopen(filepath, "r");
    if (f == NULL) return;

    char line[8192];
    while (fgets(line, sizeof(line), f) != NULL) {
        if (line[0] == '#' || line[0] == '\n') continue;
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = '\0';
        if (len == 0) continue;

        const char *domain = line;
        int tab_count = 0;
        for (const char *p = line; *p != '\0'; p++) {
            if (*p == '\t') tab_count++;
        }
        if (tab_count != 6) continue;

        char *tab = strchr(domain, '\t');
        if (tab == NULL) continue;
        *tab = '\0'; tab++;
        const char *subdomains = tab;
        tab = strchr(subdomains, '\t');
        if (tab == NULL) continue;
        *tab = '\0'; tab++;
        const char *path = tab;
        tab = strchr(path, '\t');
        if (tab == NULL) continue;
        *tab = '\0'; tab++;
        const char *secure = tab;
        tab = strchr(secure, '\t');
        if (tab == NULL) continue;
        *tab = '\0'; tab++;
        /* skip expiry column */
        tab = strchr(tab + 1, '\t');
        if (tab == NULL) continue;
        tab++;
        const char *name = tab;
        tab = strchr(name, '\t');
        if (tab == NULL) continue;
        *tab = '\0'; tab++;
        const char *value = tab;

        if (jar->count >= MAX_COOKIES) break;
        struct cookie_entry *e = &jar->entries[jar->count];
        memset(e, 0, sizeof(*e));
        copy_string(e->domain, sizeof(e->domain), domain);
        e->include_subdomains = (strcasecmp(subdomains, "TRUE") == 0);
        copy_string(e->path, sizeof(e->path), path);
        e->secure = (strcasecmp(secure, "TRUE") == 0);
        copy_string(e->name, sizeof(e->name), name);
        copy_string(e->value, sizeof(e->value), value);
        jar->count++;
    }

    fclose(f);
}
