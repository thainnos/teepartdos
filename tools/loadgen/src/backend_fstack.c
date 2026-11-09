#include "tls_loadgen.h"

#if HAVE_FSTACK

#include <ff_api.h>
#include <ff_epoll.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/ioctl.h>

static int fstack_init(app_t *app, char *err, size_t errlen) {
    char proc_id[32];
    snprintf(proc_id, sizeof(proc_id), "--proc-id=%u", app->cfg.fstack_proc_id);
    char *argv[] = {
        (char *)"tls_loadgen_fstack",
        (char *)"--conf",
        app->cfg.fstack_conf,
        (char *)"--proc-type=primary",
        proc_id,
        NULL
    };
    if (ff_init(5, argv) != 0) {
        snprintf(err, errlen, "ff_init failed; inspect F-Stack/DPDK output");
        return -1;
    }
    return 0;
}

static void fstack_cleanup(app_t *app) {
    (void)app;
}

static int fstack_socket_create(void) {
    return ff_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

static int fstack_set_nonblocking(int fd) {
    int on = 1;
    return ff_ioctl(fd, FIONBIO, &on);
}

static int fstack_set_nodelay(int fd, bool enabled) {
    int value = enabled ? 1 : 0;
    return ff_setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value));
}

static int fstack_bind_source(int fd, const char *source_address) {
    if (!source_address || source_address[0] == '\0') return 0;
    struct sockaddr_in source;
    memset(&source, 0, sizeof(source));
    source.sin_family = AF_INET;
    source.sin_port = htons(0);
    if (inet_pton(AF_INET, source_address, &source.sin_addr) != 1) {
        errno = EINVAL;
        return -1;
    }
    return ff_bind(fd, (const struct linux_sockaddr *)&source, sizeof(source));
}

static int fstack_connect_start(int fd, const struct sockaddr_in *dst) {
    return ff_connect(fd, (const struct linux_sockaddr *)dst, sizeof(*dst));
}

static int fstack_get_so_error(int fd, int *so_error) {
    socklen_t len = sizeof(*so_error);
    return ff_getsockopt(fd, SOL_SOCKET, SO_ERROR, so_error, &len);
}

static ssize_t fstack_read_fn(int fd, void *buf, size_t len) {
    return ff_read(fd, buf, len);
}

static ssize_t fstack_write_fn(int fd, const void *buf, size_t len) {
    return ff_write(fd, buf, len);
}

static int fstack_close_fn(int fd) {
    return ff_close(fd);
}

static int fstack_epoll_create(void) {
    return ff_epoll_create(0);
}

static int fstack_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    return ff_epoll_ctl(epfd, op, fd, event);
}

static int fstack_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout_ms) {
    return ff_epoll_wait(epfd, events, maxevents, timeout_ms);
}

static int fstack_loop(void *arg) {
    app_t *app = arg;
    if (app_loop_once(app, 0) != 0 || app->phase == PHASE_DONE || app->phase == PHASE_FAILED) {
        ff_stop_run();
    }
    return 0;
}

static int fstack_run(app_t *app) {
    ff_run(fstack_loop, app);
    return app->phase == PHASE_DONE ? 0 : -1;
}

static const backend_ops_t OPS = {
    .name = "fstack",
    .init = fstack_init,
    .cleanup = fstack_cleanup,
    .run = fstack_run,
    .socket_create = fstack_socket_create,
    .set_nonblocking = fstack_set_nonblocking,
    .set_nodelay = fstack_set_nodelay,
    .bind_source = fstack_bind_source,
    .connect_start = fstack_connect_start,
    .get_so_error = fstack_get_so_error,
    .read = fstack_read_fn,
    .write = fstack_write_fn,
    .close = fstack_close_fn,
    .epoll_create = fstack_epoll_create,
    .epoll_ctl = fstack_epoll_ctl,
    .epoll_wait = fstack_epoll_wait,
};

const backend_ops_t *backend_fstack_ops(void) {
    return &OPS;
}

#else

static int unavailable_init(app_t *app, char *err, size_t errlen) {
    (void)app;
    snprintf(err, errlen, "this binary was built without F-Stack support; build make fstack");
    return -1;
}

static const backend_ops_t OPS = {
    .name = "fstack-unavailable",
    .init = unavailable_init,
};

const backend_ops_t *backend_fstack_ops(void) {
    return &OPS;
}

#endif
