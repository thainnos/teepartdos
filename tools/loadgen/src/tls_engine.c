#include "tls_loadgen.h"

#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/x509_vfy.h>
#include <string.h>

int tls_new_session_cb(SSL *ssl, SSL_SESSION *session) {
    connection_t *conn = SSL_get_app_data(ssl);
    if (!conn || !SSL_SESSION_is_resumable(session)) return 0;
    if (conn->captured_session) {
        SSL_SESSION_free(conn->captured_session);
        conn->captured_session = NULL;
    }
    conn->captured_session = session;
    return 1;
}

SSL_CTX *tls_context_create(const config_t *cfg, char *err, size_t errlen) {
    ERR_clear_error();
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) goto fail;

    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) ||
        !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) ||
        !SSL_CTX_set_ciphersuites(ctx, cfg->ciphersuite) ||
        !SSL_CTX_set1_groups_list(ctx, cfg->group) ||
        !SSL_CTX_set1_sigalgs_list(ctx, cfg->signature_algorithm)) {
        goto fail_ctx;
    }

    if (cfg->verify_peer) {
        char ca_path[PATH_MAX];
        expand_user_path(cfg->ca_file, ca_path, sizeof(ca_path));
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (!SSL_CTX_load_verify_locations(ctx, ca_path, NULL)) goto fail_ctx;
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
    SSL_CTX_sess_set_new_cb(ctx, tls_new_session_cb);
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    return ctx;

fail_ctx:
    openssl_error_string(err, errlen);
    SSL_CTX_free(ctx);
    return NULL;
fail:
    openssl_error_string(err, errlen);
    return NULL;
}

int tls_prepare_connection(app_t *app, connection_t *conn, char *err, size_t errlen) {
    ERR_clear_error();
    conn->ssl = SSL_new(app->ssl_ctx);
    if (!conn->ssl) goto fail;
    SSL_set_app_data(conn->ssl, conn);
    SSL_set_connect_state(conn->ssl);

    if (app->cfg.server_name[0] != '\0') {
        if (SSL_set_tlsext_host_name(conn->ssl, app->cfg.server_name) != 1) goto fail;
        if (app->cfg.verify_hostname && SSL_set1_host(conn->ssl, app->cfg.server_name) != 1) goto fail;
    }

    conn->bio = net_bio_new(app->bio_method, app->backend, conn->fd);
    if (!conn->bio) goto fail;
    SSL_set_bio(conn->ssl, conn->bio, conn->bio);
    conn->bio = NULL;

    if (conn->resume_session) {
        if (SSL_set_session(conn->ssl, conn->resume_session) != 1) goto fail;
        SSL_SESSION_free(conn->resume_session);
        conn->resume_session = NULL;
    }
    return 0;

fail:
    openssl_error_string(err, errlen);
    return -1;
}

int tls_validate_profile(app_t *app, connection_t *conn, char *err, size_t errlen) {
    const char *version = SSL_get_version(conn->ssl);
    const SSL_CIPHER *cipher = SSL_get_current_cipher(conn->ssl);
    const char *cipher_name = cipher ? SSL_CIPHER_get_name(cipher) : "";
    int group_nid = SSL_get_negotiated_group(conn->ssl);
    bool resumed = SSL_session_reused(conn->ssl) == 1;

    if (!version || strcmp(version, "TLSv1.3") != 0) {
        snprintf(err, errlen, "unexpected TLS version: %s", version ? version : "none");
        return -1;
    }
    if (strcmp(cipher_name, app->cfg.ciphersuite) != 0) {
        snprintf(err, errlen, "unexpected ciphersuite: %s", cipher_name);
        return -1;
    }
    if (group_nid != NID_X9_62_prime256v1) {
        const char *name = SSL_get0_group_name(conn->ssl);
        snprintf(err, errlen, "unexpected negotiated group: %s", name ? name : "unknown");
        return -1;
    }
    if (resumed != conn->expected_resumed) {
        snprintf(err, errlen, "session reuse invariant failed: expected=%s actual=%s",
                 conn->expected_resumed ? "true" : "false", resumed ? "true" : "false");
        return -1;
    }
    if (app->cfg.verify_peer && SSL_get_verify_result(conn->ssl) != X509_V_OK) {
        snprintf(err, errlen, "certificate verification failed: %ld", SSL_get_verify_result(conn->ssl));
        return -1;
    }
    if (!resumed) {
        const char *sig_name = NULL;
        if (SSL_get0_peer_signature_name(conn->ssl, &sig_name) != 1 || !sig_name ||
            strcmp(sig_name, app->cfg.signature_algorithm) != 0) {
            snprintf(err, errlen, "unexpected peer signature: %s", sig_name ? sig_name : "none");
            return -1;
        }
    }
    return 0;
}
