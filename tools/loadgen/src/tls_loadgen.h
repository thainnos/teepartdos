#ifndef TLS_LOADGEN_H
#define TLS_LOADGEN_H

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>

#define TLSGEN_VERSION "0.1.5"
#define TLSGEN_MAX_STR 512
#define TLSGEN_MAX_ERR 1024
#define TLSGEN_MAX_EVENTS 4096
#define TLSGEN_NS_PER_S 1000000000ULL
#define TLSGEN_NS_PER_MS 1000000ULL
#define TLSGEN_NS_PER_US 1000ULL

#ifndef TLSGEN_GIT_COMMIT
#define TLSGEN_GIT_COMMIT "unknown"
#endif

#if OPENSSL_VERSION_NUMBER < 0x30500000L
#error "tls_loadgen requires OpenSSL 3.5 or newer"
#endif

typedef enum {
    BACKEND_POSIX = 0,
    BACKEND_FSTACK
} backend_kind_t;

typedef enum {
    WORKLOAD_FULL = 0,
    WORKLOAD_RESUMPTION,
    WORKLOAD_RECORD
} workload_t;

typedef enum {
    MODE_BENIGN = 0,
    MODE_FLOOD
} generation_mode_t;

typedef enum {
    PHASE_PREPARE = 0,
    PHASE_PRIME,
    PHASE_PREFLIGHT,
    PHASE_RECORD_SETUP,
    PHASE_RUN,
    PHASE_DRAIN,
    PHASE_DONE,
    PHASE_FAILED
} app_phase_t;

typedef enum {
    OP_NONE = 0,
    OP_FULL,
    OP_RESUME,
    OP_PRIME,
    OP_RESUME_PREFLIGHT,
    OP_RECORD_SETUP,
    OP_RECORD_TRANSACTION,
    OP_RECORD_RECONNECT
} operation_kind_t;

typedef enum {
    CONN_FREE = 0,
    CONN_TCP_CONNECTING,
    CONN_TLS_HANDSHAKE,
    CONN_APP_WRITE,
    CONN_APP_READ,
    CONN_WAIT_TICKET,
    CONN_RECORD_IDLE,
    CONN_CLOSING
} conn_state_t;

typedef enum {
    FAIL_NONE = 0,
    FAIL_LOCAL_CAPACITY,
    FAIL_SOCKET,
    FAIL_BIND,
    FAIL_CONNECT,
    FAIL_TLS_OBJECT,
    FAIL_TLS_HANDSHAKE,
    FAIL_TLS_PROFILE,
    FAIL_SESSION,
    FAIL_WRITE,
    FAIL_READ,
    FAIL_PAYLOAD,
    FAIL_TIMEOUT,
    FAIL_EPOLL
} failure_stage_t;

typedef struct {
    char target_address[64];
    uint16_t target_port;
    char target_mac[32];
    char source_address[64];
    char netmask[64];
    char source_interface[IFNAMSIZ];
    uint16_t mtu;
    bool tcp_nodelay;

    char ca_file[TLSGEN_MAX_STR];
    char server_name[TLSGEN_MAX_STR];
    bool verify_peer;
    bool verify_hostname;
    char ciphersuite[128];
    char group[64];
    char signature_algorithm[128];

    workload_t workload;
    generation_mode_t mode;
    char scenario[8];
    double rate_per_s;
    uint64_t duration_s;
    uint32_t max_inflight;
    uint32_t max_release_burst;
    uint64_t drain_timeout_ms;

    uint64_t tcp_connect_timeout_ms;
    uint64_t tls_handshake_timeout_ms;
    uint64_t io_timeout_ms;

    size_t payload_size;
    uint8_t payload_pattern;

    bool full_echo_after_handshake;
    char resumption_policy[32];
    uint32_t resumption_pool_size;
    bool resumption_wait_for_fresh_ticket;
    uint32_t record_connections;
    uint32_t record_max_pending_releases;
    bool record_reconnect;
    uint64_t record_reconnect_backoff_ms;

    char output_directory[TLSGEN_MAX_STR];
    char run_id[64];
    char fstack_conf[TLSGEN_MAX_STR];
    unsigned fstack_proc_id;
    bool stdout_progress;
} config_t;

typedef struct {
    char config_path[PATH_MAX];
    backend_kind_t backend;
    bool backend_set;
    bool workload_set;
    workload_t workload;
    bool mode_set;
    generation_mode_t mode;
    bool rate_set;
    double rate_per_s;
    bool duration_set;
    uint64_t duration_s;
    bool max_inflight_set;
    uint32_t max_inflight;
    bool record_connections_set;
    uint32_t record_connections;
    bool scenario_set;
    char scenario[8];
    bool output_set;
    char output_directory[TLSGEN_MAX_STR];
    bool run_id_set;
    char run_id[64];
    bool target_set;
    char target_address[64];
    bool port_set;
    uint16_t target_port;
    bool fstack_conf_set;
    char fstack_conf[TLSGEN_MAX_STR];
} cli_t;

struct app;
struct connection;

typedef struct backend_ops {
    const char *name;
    int (*init)(struct app *app, char *err, size_t errlen);
    void (*cleanup)(struct app *app);
    int (*run)(struct app *app);
    int (*socket_create)(void);
    int (*set_nonblocking)(int fd);
    int (*set_nodelay)(int fd, bool enabled);
    int (*bind_source)(int fd, const char *source_address);
    int (*connect_start)(int fd, const struct sockaddr_in *dst);
    int (*get_so_error)(int fd, int *so_error);
    ssize_t (*read)(int fd, void *buf, size_t len);
    ssize_t (*write)(int fd, const void *buf, size_t len);
    int (*close)(int fd);
    int (*epoll_create)(void);
    int (*epoll_ctl)(int epfd, int op, int fd, struct epoll_event *event);
    int (*epoll_wait)(int epfd, struct epoll_event *events, int maxevents, int timeout_ms);
} backend_ops_t;

typedef struct {
    uint64_t offered;
    uint64_t attempted;
    uint64_t completed;
    uint64_t local_capacity_drop;
    uint64_t session_unavailable;
    uint64_t tcp_established;
    uint64_t full_handshake_ok;
    uint64_t resumed_handshake_ok;
    uint64_t handshake_fail;
    uint64_t profile_fail;
    uint64_t app_ok;
    uint64_t app_fail;
    uint64_t payload_fail;
    uint64_t timeout_fail;
    uint64_t reconnect_attempted;
    uint64_t reconnect_ok;
    uint64_t bytes_tx;
    uint64_t bytes_rx;
} counters_t;

typedef struct {
    SSL_SESSION **items;
    size_t count;
    size_t capacity;
    size_t rr_index;
} session_pool_t;

typedef struct bio_net_ctx {
    const backend_ops_t *ops;
    int fd;
} bio_net_ctx_t;

typedef struct connection {
    uint32_t slot;
    int fd;
    conn_state_t state;
    operation_kind_t op;
    uint32_t epoll_events;
    bool epoll_registered;
    bool expected_resumed;
    bool measured;
    bool record_connection;
    bool record_ready_counted;
    bool pending_record_transaction;

    SSL *ssl;
    BIO *bio;
    SSL_SESSION *captured_session;
    SSL_SESSION *resume_session;

    uint64_t operation_id;
    uint64_t state_started_ns;
    uint64_t operation_started_ns;
    uint64_t deadline_ns;
    uint64_t retry_after_ns;

    size_t write_offset;
    size_t read_offset;
    uint8_t *read_buffer;

    failure_stage_t failure_stage;
    char error[TLSGEN_MAX_ERR];
} connection_t;

typedef struct app {
    config_t cfg;
    cli_t cli;
    const backend_ops_t *backend;
    app_phase_t phase;
    int epfd;
    SSL_CTX *ssl_ctx;
    BIO_METHOD *bio_method;
    struct sockaddr_in target_sockaddr;

    connection_t *connections;
    size_t connection_capacity;
    uint8_t *payload;
    session_pool_t sessions;

    uint64_t next_operation_id;
    uint64_t process_started_utc_ns;
    uint64_t run_started_utc_ns;
    uint64_t run_end_deadline_utc_ns;
    uint64_t run_end_observed_utc_ns;
    uint64_t drain_finished_utc_ns;
    uint64_t process_finished_utc_ns;
    uint64_t phase_started_ns;
    uint64_t run_started_ns;
    uint64_t run_end_ns;
    uint64_t next_release_ns;
    uint64_t release_interval_ns;
    uint64_t last_stats_ns;
    uint64_t drain_deadline_ns;
    uint64_t record_rr;
    uint64_t record_pending_releases;
    uint64_t record_pending_releases_max;
    uint64_t release_lag_max_ns;

    uint32_t prime_inflight;
    uint32_t record_ready;
    bool preflight_started;
    bool preflight_ok;
    bool stop_requested;

    counters_t total;
    counters_t previous;
    FILE *stats_csv;
    char stats_path[PATH_MAX];
    char metadata_path[PATH_MAX];
    char timeline_path[PATH_MAX];
    char run_end_reason[32];
    char run_dir[PATH_MAX];
    char fatal_error[TLSGEN_MAX_ERR];
} app_t;

uint64_t monotonic_ns(void);
uint64_t realtime_ns(void);
const char *workload_name(workload_t workload);
const char *mode_name(generation_mode_t mode);
const char *phase_name(app_phase_t phase);
const char *failure_name(failure_stage_t stage);
void openssl_error_string(char *out, size_t outlen);
void expand_user_path(const char *input, char *output, size_t output_len);

void config_defaults(config_t *cfg);
int config_load(const char *path, config_t *cfg, char *err, size_t errlen);
int cli_parse(int argc, char **argv, cli_t *cli, char *err, size_t errlen);
void config_apply_cli(config_t *cfg, const cli_t *cli);
int config_validate(const config_t *cfg, backend_kind_t backend, char *err, size_t errlen);
void print_usage(FILE *out, const char *argv0);

const backend_ops_t *backend_posix_ops(void);
const backend_ops_t *backend_fstack_ops(void);

BIO_METHOD *net_bio_method_create(void);
BIO *net_bio_new(BIO_METHOD *method, const backend_ops_t *ops, int fd);

SSL_CTX *tls_context_create(const config_t *cfg, char *err, size_t errlen);
int tls_prepare_connection(app_t *app, connection_t *conn, char *err, size_t errlen);
int tls_validate_profile(app_t *app, connection_t *conn, char *err, size_t errlen);
int tls_new_session_cb(SSL *ssl, SSL_SESSION *session);

int session_pool_init(session_pool_t *pool, size_t capacity);
void session_pool_free(session_pool_t *pool);
int session_pool_push(session_pool_t *pool, SSL_SESSION *session);
SSL_SESSION *session_pool_pop(session_pool_t *pool);
SSL_SESSION *session_pool_duplicate_round_robin(session_pool_t *pool);

int app_initialize(app_t *app, int argc, char **argv);
void app_cleanup(app_t *app);
int app_loop_once(app_t *app, int timeout_ms);
int app_backend_loop(app_t *app);
void app_request_stop(app_t *app);

#endif
