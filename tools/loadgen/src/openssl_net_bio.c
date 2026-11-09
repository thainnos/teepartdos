#include "tls_loadgen.h"

#include <errno.h>
#include <string.h>

static int net_bio_create(BIO *bio) {
    BIO_set_init(bio, 0);
    BIO_set_data(bio, NULL);
    BIO_set_shutdown(bio, 0);
    return 1;
}

static int net_bio_destroy(BIO *bio) {
    if (!bio) return 0;
    bio_net_ctx_t *ctx = BIO_get_data(bio);
    OPENSSL_free(ctx);
    BIO_set_data(bio, NULL);
    BIO_set_init(bio, 0);
    return 1;
}

static int net_bio_read(BIO *bio, char *buf, int len) {
    if (!buf || len <= 0) return 0;
    bio_net_ctx_t *ctx = BIO_get_data(bio);
    if (!ctx || !ctx->ops || ctx->fd < 0) return 0;
    BIO_clear_retry_flags(bio);
    ssize_t rc = ctx->ops->read(ctx->fd, buf, (size_t)len);
    if (rc > 0) return (int)rc;
    if (rc == 0) return 0;
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        BIO_set_retry_read(bio);
    }
    return -1;
}

static int net_bio_write(BIO *bio, const char *buf, int len) {
    if (!buf || len <= 0) return 0;
    bio_net_ctx_t *ctx = BIO_get_data(bio);
    if (!ctx || !ctx->ops || ctx->fd < 0) return 0;
    BIO_clear_retry_flags(bio);
    ssize_t rc = ctx->ops->write(ctx->fd, buf, (size_t)len);
    if (rc >= 0) return (int)rc;
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        BIO_set_retry_write(bio);
    }
    return -1;
}

static long net_bio_ctrl(BIO *bio, int cmd, long num, void *ptr) {
    (void)bio;
    (void)num;
    (void)ptr;
    switch (cmd) {
        case BIO_CTRL_FLUSH:
        case BIO_CTRL_DUP:
            return 1;
        case BIO_CTRL_PENDING:
        case BIO_CTRL_WPENDING:
            return 0;
        case BIO_CTRL_GET_CLOSE:
            return 0;
        case BIO_CTRL_SET_CLOSE:
            return 1;
        default:
            return 0;
    }
}

BIO_METHOD *net_bio_method_create(void) {
    BIO_METHOD *method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "tls-loadgen-net");
    if (!method) return NULL;
    if (!BIO_meth_set_create(method, net_bio_create) ||
        !BIO_meth_set_destroy(method, net_bio_destroy) ||
        !BIO_meth_set_read(method, net_bio_read) ||
        !BIO_meth_set_write(method, net_bio_write) ||
        !BIO_meth_set_ctrl(method, net_bio_ctrl)) {
        BIO_meth_free(method);
        return NULL;
    }
    return method;
}

BIO *net_bio_new(BIO_METHOD *method, const backend_ops_t *ops, int fd) {
    BIO *bio = BIO_new(method);
    if (!bio) return NULL;
    bio_net_ctx_t *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx) {
        BIO_free(bio);
        return NULL;
    }
    ctx->ops = ops;
    ctx->fd = fd;
    BIO_set_data(bio, ctx);
    BIO_set_init(bio, 1);
    return bio;
}
