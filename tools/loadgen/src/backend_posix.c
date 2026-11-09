#include "tls_loadgen.h"

#include <fcntl.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int posix_init(app_t *app, char *err, size_t errlen) {
    (void)app;
    (void)err;
    (void)errlen;
    return 0;
}

static void posix_cleanup(app_t *app) {
    (void)app;
}

static int posix_socket_create(void) {
    return socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

static int posix_set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int posix_set_nodelay(int fd, bool enabled) {
    int value = enabled ? 1 : 0;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value));
}

static int posix_bind_source(int fd, const char *source_address) {
    if (!source_address || source_address[0] == '\0') return 0;
    struct sockaddr_in source;
    memset(&source, 0, sizeof(source));
    source.sin_family = AF_INET;
    source.sin_port = htons(0);
    if (inet_pton(AF_INET, source_address, &source.sin_addr) != 1) {
        errno = EINVAL;
        return -1;
    }
    return bind(fd, (struct sockaddr *)&source, sizeof(source));
}

static int posix_connect_start(int fd, const struct sockaddr_in *dst) {
    return connect(fd, (const struct sockaddr *)dst, sizeof(*dst));
}

static int posix_get_so_error(int fd, int *so_error) {
    socklen_t len = sizeof(*so_error);
    return getsockopt(fd, SOL_SOCKET, SO_ERROR, so_error, &len);
}

static ssize_t posix_read_fn(int fd, void *buf, size_t len) {
    return read(fd, buf, len);
}

static ssize_t posix_write_fn(int fd, const void *buf, size_t len) {
    return write(fd, buf, len);
}

static int posix_close_fn(int fd) {
    return close(fd);
}

static int posix_epoll_create(void) {
    return epoll_create1(EPOLL_CLOEXEC);
}

static int posix_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    return epoll_ctl(epfd, op, fd, event);
}

static int posix_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout_ms) {
    return epoll_wait(epfd, events, maxevents, timeout_ms);
}

static int posix_run(app_t *app) {
    while (app->phase != PHASE_DONE && app->phase != PHASE_FAILED) {
        if (app_loop_once(app, 1) != 0) return -1;
    }
    return app->phase == PHASE_DONE ? 0 : -1;
}

static const backend_ops_t OPS = {
    .name = "posix",
    .init = posix_init,
    .cleanup = posix_cleanup,
    .run = posix_run,
    .socket_create = posix_socket_create,
    .set_nonblocking = posix_set_nonblocking,
    .set_nodelay = posix_set_nodelay,
    .bind_source = posix_bind_source,
    .connect_start = posix_connect_start,
    .get_so_error = posix_get_so_error,
    .read = posix_read_fn,
    .write = posix_write_fn,
    .close = posix_close_fn,
    .epoll_create = posix_epoll_create,
    .epoll_ctl = posix_epoll_ctl,
    .epoll_wait = posix_epoll_wait,
};

const backend_ops_t *backend_posix_ops(void) {
    return &OPS;
}
