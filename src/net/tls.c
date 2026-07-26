#define _GNU_SOURCE
#include "curldbg.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>

static SSL_CTX *create_tls_context(const struct tls_params *params,
                                   char *error, size_t error_len) {
    if (OPENSSL_init_ssl(0, NULL) != 1) {
        set_ssl_error(error, error_len, "OPENSSL_init_ssl failed");
        return NULL;
    }
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        set_ssl_error(error, error_len, "SSL_CTX_new failed");
        return NULL;
    }
#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
    SSL_CTX_set_options(ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_set_read_ahead(ctx, 1);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (params != NULL && (params->cacert != NULL || params->capath != NULL)) {
        if (SSL_CTX_load_verify_locations(ctx, params->cacert, params->capath) != 1) {
            set_ssl_error(error, error_len, "Could not load CA certificates");
            SSL_CTX_free(ctx);
            return NULL;
        }
    } else {
        if (SSL_CTX_load_verify_file(ctx, X509_get_default_cert_file()) != 1) {
            if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
                set_ssl_error(error, error_len, "Could not load system CA certificates");
                SSL_CTX_free(ctx);
                return NULL;
            }
        }
    }
    return ctx;
}

int init_tls(struct connection *conn, const char *hostname, bool insecure,
             int tls_min_version, int tls_max_version,
             const struct tls_params *params,
             char *error, size_t error_len) {
    SSL_CTX *ctx = create_tls_context(params, error, error_len);
    if (ctx == NULL) return -1;
    conn->ctx = ctx;

    conn->ssl = SSL_new(ctx);
    if (conn->ssl == NULL) { set_ssl_error(error, error_len, "SSL_new failed"); return -1; }

    if (tls_min_version > 0) {
        if (SSL_set_min_proto_version(conn->ssl, tls_min_version) != 1) {
            set_ssl_error(error, error_len, "Failed to set TLS min version"); return -1;
        }
    }
    if (tls_max_version > 0) {
        if (SSL_set_max_proto_version(conn->ssl, tls_max_version) != 1) {
            set_ssl_error(error, error_len, "Failed to set TLS max version"); return -1;
        }
    }

    if (SSL_set_tlsext_host_name(conn->ssl, hostname) != 1) {
        set_ssl_error(error, error_len, "Failed to set TLS SNI hostname"); return -1;
    }
    if (!insecure) {
        if (SSL_set1_host(conn->ssl, hostname) != 1) {
            set_ssl_error(error, error_len, "Failed to configure TLS hostname verification"); return -1;
        }
    } else {
        SSL_set_verify(conn->ssl, SSL_VERIFY_NONE, NULL);
    }
    if (SSL_set_fd(conn->ssl, conn->fd) != 1) {
        set_ssl_error(error, error_len, "SSL_set_fd failed"); return -1;
    }

    int connect_rc = SSL_connect(conn->ssl);
    if (connect_rc != 1) {
        int ssl_err = SSL_get_error(conn->ssl, connect_rc);
        if ((ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) ||
            (ssl_err == SSL_ERROR_SYSCALL && is_timeout_errno(errno))) {
            set_error(error, error_len, "TLS handshake timeout"); return -1;
        }
        if (ssl_err == SSL_ERROR_SYSCALL && errno != 0) {
            set_error(error, error_len, "TLS handshake failed: %s", strerror(errno)); return -1;
        }
        if (ssl_err == SSL_ERROR_SYSCALL && errno == 0) {
            set_error(error, error_len, "TLS handshake failed: unexpected EOF"); return -1;
        }
        set_ssl_error(error, error_len, "TLS handshake failed"); return -1;
    }

    if (!insecure) {
        if (SSL_get_verify_result(conn->ssl) != X509_V_OK) {
            set_error(error, error_len, "TLS certificate verification failed"); return -1;
        }
    }
    return 0;
}
