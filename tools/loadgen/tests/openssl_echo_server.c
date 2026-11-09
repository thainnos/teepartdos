#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested = 0;
static int listener_fd = -1;
static SSL_CTX *global_ctx = NULL;
static unsigned long echo_delay_us = 0;

static void on_signal(int sig) {
    (void)sig;
    stop_requested = 1;
    if (listener_fd >= 0) close(listener_fd);
}

static void *serve_client(void *arg) {
    int fd = *(int *)arg;
    free(arg);
    SSL *ssl = SSL_new(global_ctx);
    if (!ssl) { close(fd); return NULL; }
    SSL_set_fd(ssl, fd);
    if (SSL_accept(ssl) == 1) {
        unsigned char buf[16384];
        for (;;) {
            size_t n = 0;
            if (SSL_read_ex(ssl, buf, sizeof(buf), &n) != 1) break;
            if (echo_delay_us > 0) {
                struct timespec delay = {
                    .tv_sec = (time_t)(echo_delay_us / 1000000UL),
                    .tv_nsec = (long)(echo_delay_us % 1000000UL) * 1000L,
                };
                (void)nanosleep(&delay, NULL);
            }
            size_t off = 0;
            while (off < n) {
                size_t written = 0;
                if (SSL_write_ex(ssl, buf + off, n - off, &written) != 1) goto done;
                off += written;
            }
        }
    }
done:
    (void)SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s PORT CERT KEY\n", argv[0]);
        return 2;
    }
    int port = atoi(argv[1]);
    const char *delay_env = getenv("TLSGEN_TEST_ECHO_DELAY_US");
    if (delay_env && *delay_env) echo_delay_us = strtoul(delay_env, NULL, 10);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    global_ctx = SSL_CTX_new(TLS_server_method());
    if (!global_ctx) return 1;
    if (SSL_CTX_set_min_proto_version(global_ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(global_ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_ciphersuites(global_ctx, "TLS_AES_128_GCM_SHA256") != 1 ||
        SSL_CTX_set1_groups_list(global_ctx, "P-256") != 1 ||
        SSL_CTX_use_certificate_chain_file(global_ctx, argv[2]) != 1 ||
        SSL_CTX_use_PrivateKey_file(global_ctx, argv[3], SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(global_ctx) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(global_ctx);
        return 1;
    }
    SSL_CTX_set_num_tickets(global_ctx, 2);

    listener_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listener_fd < 0) return 1;
    int one = 1;
    setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(listener_fd, 256) != 0) {
        perror("listen");
        return 1;
    }
    printf("READY %d\n", port);
    fflush(stdout);

    while (!stop_requested) {
        int fd = accept(listener_fd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR || stop_requested) continue;
            perror("accept");
            break;
        }
        int *arg = malloc(sizeof(*arg));
        if (!arg) { close(fd); continue; }
        *arg = fd;
        pthread_t tid;
        if (pthread_create(&tid, NULL, serve_client, arg) != 0) {
            close(fd); free(arg); continue;
        }
        pthread_detach(tid);
    }
    if (listener_fd >= 0) close(listener_fd);
    SSL_CTX_free(global_ctx);
    return 0;
}
