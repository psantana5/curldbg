#include "curldbg.h"

#include <stdio.h>
#include <string.h>

static void copy_bounded(char *dst, size_t dst_size, const char *src) {
    size_t len = strlen(src);
    if (len >= dst_size) len = dst_size - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

/* Parse [http(s)://]host[:port][/path] into host/port/path. */
int parse_url(const char *url, struct url_info *out) {
    const char *authority_start, *path_start;
    char authority[512];
    size_t authority_len;

    if (strncasecmp(url, "http://", 7) == 0) {
        authority_start = url + 7;
        out->use_tls = false;
        snprintf(out->port, sizeof(out->port), "80");
    } else if (strncasecmp(url, "https://", 8) == 0) {
        authority_start = url + 8;
        out->use_tls = true;
        snprintf(out->port, sizeof(out->port), "443");
    } else {
        if (strstr(url, "://") != NULL) return -1;
        authority_start = url;
        out->use_tls = true;
        snprintf(out->port, sizeof(out->port), "443");
    }

    out->has_explicit_port = false;
    path_start = strchr(authority_start, '/');
    authority_len = path_start ? (size_t)(path_start - authority_start) : strlen(authority_start);

    if (authority_len == 0 || authority_len >= sizeof(authority)) return -1;
    memcpy(authority, authority_start, authority_len);
    authority[authority_len] = '\0';

    {
        char *at = strrchr(authority, '@');
        if (at != NULL) {
            *at = '\0';
            char *colon = strchr(authority, ':');
            if (colon != NULL) {
                *colon = '\0';
                if (strlen(authority) >= sizeof(out->user) || strlen(colon + 1) >= sizeof(out->pass))
                    return -1;
                copy_bounded(out->user, sizeof(out->user), authority);
                copy_bounded(out->pass, sizeof(out->pass), colon + 1);
            } else {
                if (strlen(authority) >= sizeof(out->user)) return -1;
                copy_bounded(out->user, sizeof(out->user), authority);
                out->pass[0] = '\0';
            }
            memmove(authority, at + 1, strlen(at + 1) + 1);
        }
    }

    if (authority[0] == '[') {
        char *closing = strchr(authority, ']');
        if (closing == NULL) return -1;
        *closing = '\0';
        if (strlen(authority + 1) >= sizeof(out->host)) return -1;
        copy_bounded(out->host, sizeof(out->host), authority + 1);
        if (*(closing + 1) == ':') {
            if (strlen(closing + 2) == 0 || strlen(closing + 2) >= sizeof(out->port)) return -1;
            copy_bounded(out->port, sizeof(out->port), closing + 2);
            out->has_explicit_port = true;
        } else if (*(closing + 1) != '\0') {
            return -1;
        }
    } else {
        char *colon = strrchr(authority, ':');
        if (colon != NULL) {
            *colon = '\0';
            if (strlen(colon + 1) == 0 || strlen(colon + 1) >= sizeof(out->port)) return -1;
            copy_bounded(out->port, sizeof(out->port), colon + 1);
            out->has_explicit_port = true;
        }
        if (strlen(authority) == 0 || strlen(authority) >= sizeof(out->host)) return -1;
        copy_bounded(out->host, sizeof(out->host), authority);
    }

    if (path_start == NULL) {
        snprintf(out->path, sizeof(out->path), "/");
    } else {
        if (strlen(path_start) >= sizeof(out->path)) return -1;
        copy_bounded(out->path, sizeof(out->path), path_start);
    }
    return 0;
}

int format_absolute_uri(const struct url_info *url, char *out, size_t out_size) {
    const char *scheme = url->use_tls ? "https" : "http";
    bool is_ipv6_literal = strchr(url->host, ':') != NULL;
    int n;
    if (url->has_explicit_port) {
        if (is_ipv6_literal)
            n = snprintf(out, out_size, "%s://[%s]:%s%s", scheme, url->host, url->port, url->path);
        else
            n = snprintf(out, out_size, "%s://%s:%s%s", scheme, url->host, url->port, url->path);
    } else {
        if (is_ipv6_literal)
            n = snprintf(out, out_size, "%s://[%s]%s", scheme, url->host, url->path);
        else
            n = snprintf(out, out_size, "%s://%s%s", scheme, url->host, url->path);
    }
    if (n < 0 || (size_t)n >= out_size) {
        if (out_size > 0) out[0] = '\0';
        return -1;
    }
    return 0;
}

int format_url(const struct url_info *url, char *out_url, size_t out_size) {
    const char *scheme = url->use_tls ? "https" : "http";
    bool is_ipv6_literal = strchr(url->host, ':') != NULL;
    int n;
    if (url->has_explicit_port) {
        if (is_ipv6_literal)
            n = snprintf(out_url, out_size, "%s://[%s]:%s%s", scheme, url->host, url->port, url->path);
        else
            n = snprintf(out_url, out_size, "%s://%s:%s%s", scheme, url->host, url->port, url->path);
    } else {
        if (is_ipv6_literal)
            n = snprintf(out_url, out_size, "%s://[%s]%s", scheme, url->host, url->path);
        else
            n = snprintf(out_url, out_size, "%s://%s%s", scheme, url->host, url->path);
    }
    if (n < 0 || (size_t)n >= out_size) return -1;
    return 0;
}

int format_host_header(const struct url_info *url, char *out, size_t out_size) {
    bool is_ipv6_literal = strchr(url->host, ':') != NULL;
    int n;
    if (url->has_explicit_port) {
        if (is_ipv6_literal)
            n = snprintf(out, out_size, "[%s]:%s", url->host, url->port);
        else
            n = snprintf(out, out_size, "%s:%s", url->host, url->port);
    } else {
        if (is_ipv6_literal)
            n = snprintf(out, out_size, "[%s]", url->host);
        else
            n = snprintf(out, out_size, "%s", url->host);
    }
    if (n < 0 || (size_t)n >= out_size) {
        if (out_size > 0) out[0] = '\0';
        return -1;
    }
    return 0;
}

int build_redirect_url(
    const char *location, const struct url_info *base,
    char *out_url, size_t out_size
) {
    const char *scheme = base->use_tls ? "https" : "http";
    bool is_ipv6_literal = strchr(base->host, ':') != NULL;
    const char *path_to_use;
    char base_dir[1024];
    int n;

    if (strncasecmp(location, "http://", 7) == 0 || strncasecmp(location, "https://", 8) == 0) {
        if (contains_crlf(location)) return -1;
        if (strlen(location) >= out_size) return -1;
        snprintf(out_url, out_size, "%s", location);
        return 0;
    }

    if (location[0] == '/' && location[1] == '/') {
        const char *proto = base->use_tls ? "https:" : "http:";
        if (contains_crlf(location)) return -1;
        if (strlen(proto) + strlen(location) >= out_size) return -1;
        snprintf(out_url, out_size, "%s%s", proto, location);
        return 0;
    }

    if (location[0] == '/') {
        if (contains_crlf(location)) return -1;
        path_to_use = location;
    } else {
        /* Relative path: resolve against base path directory */
        strncpy(base_dir, base->path, sizeof(base_dir) - 1);
        base_dir[sizeof(base_dir) - 1] = '\0';
        char *last_slash = strrchr(base_dir, '/');
        if (last_slash != NULL) {
            size_t keep = (size_t)(last_slash + 1 - base_dir);
            if (keep < sizeof(base_dir))
                base_dir[keep] = '\0';
        }
        if (snprintf(base_dir + strlen(base_dir), sizeof(base_dir) - strlen(base_dir), "%s", location) >=
            (int)(sizeof(base_dir) - strlen(base_dir)))
            return -1;
        path_to_use = base_dir;
    }

    if (base->has_explicit_port) {
        if (is_ipv6_literal)
            n = snprintf(out_url, out_size, "%s://[%s]:%s%s", scheme, base->host, base->port, path_to_use);
        else
            n = snprintf(out_url, out_size, "%s://%s:%s%s", scheme, base->host, base->port, path_to_use);
    } else {
        if (is_ipv6_literal)
            n = snprintf(out_url, out_size, "%s://[%s]%s", scheme, base->host, path_to_use);
        else
            n = snprintf(out_url, out_size, "%s://%s%s", scheme, base->host, path_to_use);
    }
    if (n < 0 || (size_t)n >= out_size) return -1;
    return 0;
}

int output_filename_from_url(const char *input_url, char *out, size_t out_size) {
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
