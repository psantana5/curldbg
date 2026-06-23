#define _GNU_SOURCE
#include "curldbg.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>

struct tls_params g_tls_params = {NULL, NULL};

static SSL_CTX *g_shared_tls_ctx = NULL;
static pthread_once_t g_tls_ctx_once = PTHREAD_ONCE_INIT;
static int g_tls_ctx_init_status = -1;
static char g_tls_ctx_init_error[256];

static void init_shared_tls_ctx_once(void) {
    g_tls_ctx_init_error[0] = '\0';
    if (OPENSSL_init_ssl(0, NULL) != 1) {
        set_ssl_error(g_tls_ctx_init_error, sizeof(g_tls_ctx_init_error), "OPENSSL_init_ssl failed");
        return;
    }
    g_shared_tls_ctx = SSL_CTX_new(TLS_client_method());
    if (g_shared_tls_ctx == NULL) {
        set_ssl_error(g_tls_ctx_init_error, sizeof(g_tls_ctx_init_error), "SSL_CTX_new failed");
        return;
    }
#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
    SSL_CTX_set_options(g_shared_tls_ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif
    SSL_CTX_set_session_cache_mode(g_shared_tls_ctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_set_verify(g_shared_tls_ctx, SSL_VERIFY_PEER, NULL);
    if (g_tls_params.cacert != NULL || g_tls_params.capath != NULL) {
        if (SSL_CTX_load_verify_locations(g_shared_tls_ctx, g_tls_params.cacert, g_tls_params.capath) != 1) {
            set_ssl_error(g_tls_ctx_init_error, sizeof(g_tls_ctx_init_error), "Could not load CA certificates");
            SSL_CTX_free(g_shared_tls_ctx);
            g_shared_tls_ctx = NULL;
            return;
        }
    } else {
        if (SSL_CTX_load_verify_file(g_shared_tls_ctx, X509_get_default_cert_file()) != 1) {
            if (SSL_CTX_set_default_verify_paths(g_shared_tls_ctx) != 1) {
                set_ssl_error(g_tls_ctx_init_error, sizeof(g_tls_ctx_init_error), "Could not load system CA certificates");
                SSL_CTX_free(g_shared_tls_ctx);
                g_shared_tls_ctx = NULL;
                return;
            }
        }
    }
    g_tls_ctx_init_status = 0;
}

static int get_shared_tls_ctx(SSL_CTX **ctx, char *error, size_t error_len) {
    int rc = pthread_once(&g_tls_ctx_once, init_shared_tls_ctx_once);
    if (rc != 0) {
        set_error(error, error_len, "pthread_once failed: %s", strerror(rc));
        return -1;
    }
    if (g_tls_ctx_init_status != 0 || g_shared_tls_ctx == NULL) {
        if (g_tls_ctx_init_error[0] != '\0')
            set_error(error, error_len, "%s", g_tls_ctx_init_error);
        else
            set_error(error, error_len, "TLS context initialization failed");
        return -1;
    }
    *ctx = g_shared_tls_ctx;
    return 0;
}

void warmup_tls(void) {
    SSL_CTX *ctx = NULL;
    char err[256];
    (void)get_shared_tls_ctx(&ctx, err, sizeof(err));
}

int init_tls(struct connection *conn, const char *hostname, bool insecure,
             int tls_min_version, int tls_max_version,
             char *error, size_t error_len) {
    SSL_CTX *shared_ctx = NULL;
    if (get_shared_tls_ctx(&shared_ctx, error, error_len) != 0) return -1;

    conn->ssl = SSL_new(shared_ctx);
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
