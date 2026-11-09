#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "psa/crypto.h"

#include "mbedtls/asn1write.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/ecp.h"
#include "mbedtls/error.h"
#include "mbedtls/md.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/private_access.h"
#include "mbedtls/pk.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cache.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ssl_ticket.h"
#include "mbedtls/version.h"
#include "mbedtls/x509_crt.h"

#include "tee_km_client.h"
#include "tee_sign_client.h"
#include "tee_tls_d_client.h"
#include "ta_key_mgmt.h"
#include "ta_privkey_sign.h"

#if !defined(MBEDTLS_SSL_ASYNC_PRIVATE)
#error "Scenario E requires MBEDTLS_SSL_ASYNC_PRIVATE"
#endif

#if !defined(MBEDTLS_SSL_TLS1_3_SERVER_EXTERNAL_SIGNING)
#error "Scenario E requires the local TLS 1.3 server external-signing patch"
#endif

#if !defined(MBEDTLS_SSL_TLS1_3_CRYPTO_BACKEND)
#error "Scenario E requires the D4 TLS 1.3 crypto backend"
#endif

#if !defined(MBEDTLS_SSL_L1_PATCH_VERSION) || \
    MBEDTLS_SSL_L1_PATCH_VERSION < 1
#error "Scenario E requires Mbed TLS L1 patch version 1 or newer"
#endif

/*
 * Scenario E Case-A TLS echo server.
 *
 * Purpose:
 *   Literal composition of the secret-protection mechanisms implemented by
 *   Scenarios B, C and D on the common D4 Mbed TLS basis.
 *
 *   - Scenario B: serialize TLS 1.3 session state in the REE and protect the
 *     resulting ticket blob with the Scenario B OP-TEE key-management TA.
 *   - Scenario C: provision the ECDSA P-256 server key into the Scenario C TA
 *     and perform TLS 1.3 CertificateVerify signing through the external-sign
 *     callback. The parsed REE private-key context is released before accept.
 *   - Scenario D4: use the Scenario D TA for server ECDHE, key schedules,
 *     Finished, traffic keys/IVs, record sequence state, record AES-GCM and
 *     resumption-master/ticket-PSK derivation.
 *
 * This is intentionally the literal composition. It does not add opaque PSK
 * binder processing or opaque resumption state beyond Scenario B.
 *
 * Fixed TLS profile:
 *   - TLS 1.3 only
 *   - TLS_AES_128_GCM_SHA256
 *   - ecdsa_secp256r1_sha256
 *   - secp256r1 for ECDHE
 *   - server authentication only; no mutual TLS
 *   - 0-RTT disabled; KeyUpdate out of scope
 */
#define SCENARIO_E_BUILD_ID           "scenario-e-case-a-common-d4-v1"

#define DEFAULT_BIND_IP              "0.0.0.0"
#define DEFAULT_PORT                 "4433"
#define DEFAULT_CERT_PATH            "./server.crt"
#define DEFAULT_KEY_PATH             "./server.key"
#define DEFAULT_LOG_PATH             "./tls_echo_server_e.log"
#define DEFAULT_MAX_PAYLOAD          (16U * 1024U)
#define DEFAULT_LISTEN_BACKLOG       128
#define DEFAULT_MAX_EVENTS           64
#define DEFAULT_MAX_CONNECTIONS      256
#define DEFAULT_HANDSHAKE_TIMEOUT_MS 30000
#define DEFAULT_IDLE_TIMEOUT_MS      30000
#define DEFAULT_CACHE_TIMEOUT_SEC    300
#define DEFAULT_CACHE_MAX_ENTRIES    256
#define DEFAULT_SUMMARY_INTERVAL_MS  1000
#define DEFAULT_TICKET_LIFETIME_SEC  300
#define RNG_PERS_STRING              "scenario-e-case-a-mbedtls-tls13-echo"
#define DEFAULT_TICKET_PLAIN_CAP      (8U * 1024U)

/* Static lifetime required: Mbed TLS stores pointers to these arrays. */
static const int g_tls13_ciphersuites[] = {
    MBEDTLS_TLS1_3_AES_128_GCM_SHA256,
    0
};

static const uint16_t g_tls13_groups[] = {
    MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1,
    0
};

static const uint16_t g_tls13_sig_algs[] = {
    MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256,
    MBEDTLS_TLS1_3_SIG_NONE
};

typedef enum {
    LOG_MODE_MEASUREMENT = 0,
    LOG_MODE_DEBUG = 1
} log_mode_t;

typedef enum {
    CLOSE_REASON_UNSPECIFIED = 0,
    CLOSE_REASON_PEER_CLOSED,
    CLOSE_REASON_PEER_HANGUP,
    CLOSE_REASON_HANDSHAKE_FAILURE,
    CLOSE_REASON_HANDSHAKE_TIMEOUT,
    CLOSE_REASON_IDLE_TIMEOUT,
    CLOSE_REASON_SSL_READ_FAILURE,
    CLOSE_REASON_SSL_WRITE_FAILURE,
    CLOSE_REASON_PAYLOAD_LIMIT,
    CLOSE_REASON_SERVER_SHUTDOWN
} close_reason_t;

typedef struct {
    char bind_ip[64];
    char port[16];
    char cert_path[512];
    char key_path[512];
    char log_path[512];

    size_t max_payload;
    int listen_backlog;
    int max_events;
    int max_connections;
    int handshake_timeout_ms;
    int idle_timeout_ms;
    int cache_timeout_sec;
    int cache_max_entries;
    int summary_interval_ms;
    int ticket_lifetime_sec;

    bool session_cache_enabled;
    bool session_tickets_enabled;
    bool strict_cert_profile;
    bool tee_ticket_protection_enabled;
    bool external_signing_enabled;
    bool crypto_backend_enabled;
    bool tee_selftest_enabled;
    bool async_debug_events;
    bool ticket_debug_hashes;
    size_t ticket_plain_cap;

    log_mode_t log_mode;
    int debug_level;
} server_config_t;

typedef struct {
    uint64_t accepted_total;
    uint64_t dropped_no_slot;
    uint64_t active_connections;

    uint64_t handshake_success;
    uint64_t handshake_failure;
    uint64_t handshake_timeout;
    uint64_t handshake_duration_sum_us;
    uint64_t handshake_duration_max_us;

    uint64_t ticket_write_attempt;
    uint64_t ticket_write_success;
    uint64_t ticket_write_failure;
    uint64_t ticket_parse_attempt;
    uint64_t ticket_parse_success;
    uint64_t ticket_parse_failure;

    uint64_t tee_init_success;
    uint64_t tee_init_failure;
    uint64_t tee_selftest_success;
    uint64_t tee_selftest_failure;
    uint64_t backend_connection_init_success;
    uint64_t backend_connection_init_failure;
    uint64_t backend_connection_free_calls;
    uint64_t tee_connection_open_success;
    uint64_t tee_connection_open_failure;
    uint64_t tee_connection_close_success;
    uint64_t tee_connection_close_failure;
    uint64_t backend_transform_free_calls;
    uint64_t backend_transform_import_success;
    uint64_t backend_transform_import_failure;
    uint64_t tee_transform_import_success;
    uint64_t tee_transform_import_failure;
    uint64_t tee_transform_free_success;
    uint64_t tee_transform_free_failure;
    uint64_t record_seal_success;
    uint64_t record_seal_failure;
    uint64_t record_open_success;
    uint64_t record_open_failure;
    uint64_t backend_handshake_keys_success;
    uint64_t backend_handshake_keys_failure;
    uint64_t tee_handshake_keys_success;
    uint64_t tee_handshake_keys_failure;
    uint64_t backend_application_keys_success;
    uint64_t backend_application_keys_failure;
    uint64_t tee_application_keys_success;
    uint64_t tee_application_keys_failure;
    uint64_t finished_success;
    uint64_t finished_failure;
    uint64_t tee_finished_success;
    uint64_t tee_finished_failure;
    uint64_t backend_server_key_share_success;
    uint64_t backend_server_key_share_failure;
    uint64_t tee_server_key_share_success;
    uint64_t tee_server_key_share_failure;
    uint64_t backend_resumption_master_success;
    uint64_t backend_resumption_master_failure;
    uint64_t tee_resumption_master_success;
    uint64_t tee_resumption_master_failure;
    uint64_t backend_resumption_psk_success;
    uint64_t backend_resumption_psk_failure;
    uint64_t tee_resumption_psk_success;
    uint64_t tee_resumption_psk_failure;

    uint64_t km_init_success;
    uint64_t km_init_failure;
    uint64_t km_selftest_success;
    uint64_t km_selftest_failure;
    uint64_t km_wrap_attempt;
    uint64_t km_wrap_success;
    uint64_t km_wrap_failure;
    uint64_t km_unwrap_attempt;
    uint64_t km_unwrap_success;
    uint64_t km_unwrap_failure;
    uint64_t km_call_duration_sum_us;
    uint64_t km_call_duration_max_us;

    uint64_t sign_init_success;
    uint64_t sign_init_failure;
    uint64_t sign_import_attempt;
    uint64_t sign_import_success;
    uint64_t sign_import_failure;
    uint64_t sign_selftest_success;
    uint64_t sign_selftest_failure;
    uint64_t sign_attempt;
    uint64_t sign_success;
    uint64_t sign_failure;
    uint64_t sign_call_duration_sum_us;
    uint64_t sign_call_duration_max_us;
    uint64_t async_sign_start_calls;
    uint64_t async_resume_calls;
    uint64_t async_cancel_calls;

    uint64_t echo_read_events;
    uint64_t echo_write_events;
    uint64_t echo_responses_completed;
    uint64_t bytes_rx;
    uint64_t bytes_tx;

    uint64_t ssl_read_failure;
    uint64_t ssl_write_failure;
    uint64_t payload_limit_exceeded;
    uint64_t idle_timeout;
    uint64_t peer_closed;
    uint64_t peer_hangup;

    uint64_t epoll_wait_calls;
    uint64_t epoll_events;
    uint64_t want_read_returns;
    uint64_t want_write_returns;
} server_counters_t;

typedef struct server_ctx_s server_ctx_t;

struct server_ctx_s {
    FILE *log_fp;
    server_config_t cfg;
    server_counters_t counters;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt cert;
    mbedtls_pk_context pkey;
    mbedtls_ssl_config ssl_conf;
    mbedtls_ssl_cache_context ssl_cache;
    mbedtls_ssl_ticket_context ticket_ctx;
    bool ticket_ctx_initialized;

    tee_km_client_t tee_km;
    bool tee_km_initialized;
    unsigned char *ticket_plain_buf;
    size_t ticket_plain_cap;

    tee_sign_client_t tee_sign;
    bool tee_sign_initialized;
    bool provisioning_key_released;

    tee_tls_d_client_t tee_client;
    bool tee_client_initialized;
    mbedtls_ssl_tls13_crypto_backend crypto_backend;

    struct timespec start_ts;
    struct timespec last_summary_ts;
};

typedef struct client_ctx_s {
    bool in_use;
    int slot_index;
    int fd;
    mbedtls_net_context net;
    mbedtls_ssl_context ssl;

    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;
    char peer_str[INET6_ADDRSTRLEN + 16];

    bool handshake_done;
    bool handshake_ok;
    bool echoed_once;
    bool want_read;
    bool want_write;

    uint8_t *out_buf;
    size_t out_cap;
    size_t out_len;
    size_t out_off;

    uint64_t bytes_rx;
    uint64_t bytes_tx;
    uint64_t handshake_duration_us;

    struct timespec accepted_ts;
    struct timespec last_activity_ts;
    struct timespec handshake_start_ts;
} client_ctx_t;

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int signo) {
    (void) signo;
    g_stop = 1;
}

static void ts_now(struct timespec *ts) {
    clock_gettime(CLOCK_MONOTONIC, ts);
}

static uint64_t ts_diff_us(const struct timespec *start, const struct timespec *end) {
    int64_t sec = (int64_t) end->tv_sec - (int64_t) start->tv_sec;
    int64_t nsec = (int64_t) end->tv_nsec - (int64_t) start->tv_nsec;
    return (uint64_t) (sec * 1000000LL + nsec / 1000LL);
}

static const char *wallclock_iso8601(char *buf, size_t len) {
    struct timespec ts;
    struct tm tmv;
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tmv);
    snprintf(buf, len, "%04d-%02d-%02dT%02d:%02d:%02d.%03ld",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec, ts.tv_nsec / 1000000L);
    return buf;
}

static void log_line(server_ctx_t *srv, bool debug_only, const char *level, const char *fmt, ...) {
    if (debug_only && srv->cfg.log_mode != LOG_MODE_DEBUG) {
        return;
    }

    char tsbuf[64];
    va_list ap;

    if (srv->log_fp) {
        fprintf(srv->log_fp, "[%s] %-5s ", wallclock_iso8601(tsbuf, sizeof(tsbuf)), level);
        va_start(ap, fmt);
        vfprintf(srv->log_fp, fmt, ap);
        va_end(ap);
        fputc('\n', srv->log_fp);

        if (!debug_only || srv->cfg.log_mode == LOG_MODE_DEBUG) {
            fflush(srv->log_fp);
        }
    }

    if (!debug_only || srv->cfg.log_mode == LOG_MODE_DEBUG) {
        fprintf(stdout, "[%s] %-5s ", wallclock_iso8601(tsbuf, sizeof(tsbuf)), level);
        va_start(ap, fmt);
        vfprintf(stdout, fmt, ap);
        va_end(ap);
        fputc('\n', stdout);
        fflush(stdout);
    }
}

static void mbedtls_debug_cb(void *ctx, int level, const char *file, int line, const char *str) {
    server_ctx_t *srv = (server_ctx_t *) ctx;
    if (srv->cfg.log_mode != LOG_MODE_DEBUG || level > srv->cfg.debug_level) {
        return;
    }

    char tsbuf[64];
    if (srv->log_fp) {
        fprintf(srv->log_fp, "[%s] MDBG  %s:%d: %s", wallclock_iso8601(tsbuf, sizeof(tsbuf)), file, line, str);
        fflush(srv->log_fp);
    }
}

static void format_mbedtls_error(int ret, char *buf, size_t len) {
    if (buf == NULL || len == 0) {
        return;
    }
    mbedtls_strerror(ret, buf, len);
}

static void default_config(server_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->bind_ip, sizeof(cfg->bind_ip), "%s", DEFAULT_BIND_IP);
    snprintf(cfg->port, sizeof(cfg->port), "%s", DEFAULT_PORT);
    snprintf(cfg->cert_path, sizeof(cfg->cert_path), "%s", DEFAULT_CERT_PATH);
    snprintf(cfg->key_path, sizeof(cfg->key_path), "%s", DEFAULT_KEY_PATH);
    snprintf(cfg->log_path, sizeof(cfg->log_path), "%s", DEFAULT_LOG_PATH);

    cfg->max_payload = DEFAULT_MAX_PAYLOAD;
    cfg->listen_backlog = DEFAULT_LISTEN_BACKLOG;
    cfg->max_events = DEFAULT_MAX_EVENTS;
    cfg->max_connections = DEFAULT_MAX_CONNECTIONS;
    cfg->handshake_timeout_ms = DEFAULT_HANDSHAKE_TIMEOUT_MS;
    cfg->idle_timeout_ms = DEFAULT_IDLE_TIMEOUT_MS;
    cfg->cache_timeout_sec = DEFAULT_CACHE_TIMEOUT_SEC;
    cfg->cache_max_entries = DEFAULT_CACHE_MAX_ENTRIES;
    cfg->summary_interval_ms = DEFAULT_SUMMARY_INTERVAL_MS;
    cfg->ticket_lifetime_sec = DEFAULT_TICKET_LIFETIME_SEC;

    cfg->session_cache_enabled = false;
    cfg->session_tickets_enabled = false;
    cfg->strict_cert_profile = true;
    cfg->tee_ticket_protection_enabled = true;
    cfg->external_signing_enabled = true;
    cfg->crypto_backend_enabled = true;
    cfg->tee_selftest_enabled = true;
    cfg->async_debug_events = true;
    cfg->ticket_debug_hashes = true;
    cfg->ticket_plain_cap = DEFAULT_TICKET_PLAIN_CAP;

    cfg->log_mode = LOG_MODE_MEASUREMENT;
    cfg->debug_level = 0;
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [options]\n"
            "  --bind-ip <ip>                  Bind IPv4 address (default: %s)\n"
            "  --port <port>                   Listen port (default: %s)\n"
            "  --cert <path>                   Server certificate PEM (default: %s)\n"
            "  --key <path>                    Server private key PEM (default: %s)\n"
            "  --log-file <path>               Log file path (default: %s)\n"
            "  --log-mode measurement|debug    Logging mode (default: measurement)\n"
            "  --max-payload <bytes>           Per-connection pending echo buffer cap (default: %u)\n"
            "  --listen-backlog <n>            Listen backlog (default: %d)\n"
            "  --max-events <n>                epoll wait batch size (default: %d)\n"
            "  --max-connections <n>           Max simultaneous client slots (default: %d)\n"
            "  --handshake-timeout-ms <n>      Handshake timeout in ms (default: %d)\n"
            "  --idle-timeout-ms <n>           Idle timeout in ms (default: %d)\n"
            "  --summary-interval-ms <n>       Periodic summary interval in ms (default: %d)\n"
            "  --session-cache on|off          Enable server session cache (default: off)\n"
            "  --session-tickets on|off        Enable TLS 1.3 session tickets (default: off)\n"
            "  --cache-timeout-sec <n>         Session cache/ticket lifetime seconds (default: %d)\n"
            "  --cache-max-entries <n>         Session cache max entries (default: %d)\n"
            "  --strict-cert-profile on|off    Require ECDSA-capable cert/key (default: on)\n"
            "  --tee-ticket-protection on|off  Use Scenario B TA ticket wrapping (default: on)\n"
            "  --external-signing on|off       Use Scenario C TA CertificateVerify signing (default: on)\n"
            "  --crypto-backend on|off         Use Scenario D4 ECDHE/key-schedule/record backend (default: on)\n"
            "  --tee-selftest on|off           Run enabled TA self-tests at startup (default: on)\n"
            "  --async-debug-events on|off     Log Scenario C callback events in debug mode (default: on)\n"
            "  --ticket-debug-hashes on|off    Log protected ticket SHA-256 in debug mode (default: on)\n"
            "  --ticket-plain-cap <bytes>      Max serialized session-state buffer (default: %u)\n"
            "  --debug-level <0-4>             Mbed TLS debug level in debug mode (default: %d)\n"
            "  --help                          Show this help\n",
            prog, DEFAULT_BIND_IP, DEFAULT_PORT, DEFAULT_CERT_PATH, DEFAULT_KEY_PATH, DEFAULT_LOG_PATH,
            DEFAULT_MAX_PAYLOAD, DEFAULT_LISTEN_BACKLOG, DEFAULT_MAX_EVENTS, DEFAULT_MAX_CONNECTIONS,
            DEFAULT_HANDSHAKE_TIMEOUT_MS, DEFAULT_IDLE_TIMEOUT_MS, DEFAULT_SUMMARY_INTERVAL_MS,
            DEFAULT_CACHE_TIMEOUT_SEC, DEFAULT_CACHE_MAX_ENTRIES,
            DEFAULT_TICKET_PLAIN_CAP, 0);
}

static int parse_positive_int(const char *s, int *out) {
    char *end = NULL;
    long v;
    if (s == NULL) {
        return -1;
    }
    v = strtol(s, &end, 10);
    if (*s == '\0' || end == s || *end != '\0' || v <= 0 || v > INT_MAX) {
        return -1;
    }
    *out = (int) v;
    return 0;
}

static int parse_nonnegative_int(const char *s, int *out) {
    char *end = NULL;
    long v;
    if (s == NULL) {
        return -1;
    }
    v = strtol(s, &end, 10);
    if (*s == '\0' || end == s || *end != '\0' || v < 0 || v > INT_MAX) {
        return -1;
    }
    *out = (int) v;
    return 0;
}

static int parse_size_t_value(const char *s, size_t *out) {
    char *end = NULL;
    unsigned long long v;
    if (s == NULL) {
        return -1;
    }
    v = strtoull(s, &end, 10);
    if (*s == '\0' || end == s || *end != '\0' || v == 0ULL || v > SIZE_MAX) {
        return -1;
    }
    *out = (size_t) v;
    return 0;
}

static int parse_on_off(const char *s, bool *out) {
    if (strcmp(s, "on") == 0 || strcmp(s, "yes") == 0 || strcmp(s, "true") == 0 || strcmp(s, "1") == 0) {
        *out = true;
        return 0;
    }
    if (strcmp(s, "off") == 0 || strcmp(s, "no") == 0 || strcmp(s, "false") == 0 || strcmp(s, "0") == 0) {
        *out = false;
        return 0;
    }
    return -1;
}

static int parse_args(int argc, char **argv, server_config_t *cfg) {
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 1;
        } else if (strcmp(argv[i], "--bind-ip") == 0 && i + 1 < argc) {
            snprintf(cfg->bind_ip, sizeof(cfg->bind_ip), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            snprintf(cfg->port, sizeof(cfg->port), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            snprintf(cfg->cert_path, sizeof(cfg->cert_path), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            snprintf(cfg->key_path, sizeof(cfg->key_path), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--log-file") == 0 && i + 1 < argc) {
            snprintf(cfg->log_path, sizeof(cfg->log_path), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--log-mode") == 0 && i + 1 < argc) {
            const char *mode = argv[++i];
            if (strcmp(mode, "measurement") == 0) {
                cfg->log_mode = LOG_MODE_MEASUREMENT;
            } else if (strcmp(mode, "debug") == 0) {
                cfg->log_mode = LOG_MODE_DEBUG;
            } else {
                return -1;
            }
        } else if (strcmp(argv[i], "--max-payload") == 0 && i + 1 < argc) {
            if (parse_size_t_value(argv[++i], &cfg->max_payload) != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--listen-backlog") == 0 && i + 1 < argc) {
            if (parse_positive_int(argv[++i], &cfg->listen_backlog) != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--max-events") == 0 && i + 1 < argc) {
            if (parse_positive_int(argv[++i], &cfg->max_events) != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--max-connections") == 0 && i + 1 < argc) {
            if (parse_positive_int(argv[++i], &cfg->max_connections) != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--handshake-timeout-ms") == 0 && i + 1 < argc) {
            if (parse_positive_int(argv[++i], &cfg->handshake_timeout_ms) != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--idle-timeout-ms") == 0 && i + 1 < argc) {
            if (parse_positive_int(argv[++i], &cfg->idle_timeout_ms) != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--summary-interval-ms") == 0 && i + 1 < argc) {
            if (parse_positive_int(argv[++i], &cfg->summary_interval_ms) != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--session-cache") == 0 && i + 1 < argc) {
            if (parse_on_off(argv[++i], &cfg->session_cache_enabled) != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--session-tickets") == 0 && i + 1 < argc) {
            if (parse_on_off(argv[++i], &cfg->session_tickets_enabled) != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--cache-timeout-sec") == 0 && i + 1 < argc) {
            if (parse_positive_int(argv[++i], &cfg->cache_timeout_sec) != 0) {
                return -1;
            }
            cfg->ticket_lifetime_sec = cfg->cache_timeout_sec;
        } else if (strcmp(argv[i], "--cache-max-entries") == 0 && i + 1 < argc) {
            if (parse_positive_int(argv[++i], &cfg->cache_max_entries) != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--strict-cert-profile") == 0 && i + 1 < argc) {
            if (parse_on_off(argv[++i], &cfg->strict_cert_profile) != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--tee-ticket-protection") == 0 && i + 1 < argc) {
            if (parse_on_off(argv[++i], &cfg->tee_ticket_protection_enabled) != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--external-signing") == 0 && i + 1 < argc) {
            if (parse_on_off(argv[++i], &cfg->external_signing_enabled) != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--crypto-backend") == 0 && i + 1 < argc) {
            if (parse_on_off(argv[++i], &cfg->crypto_backend_enabled) != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--tee-selftest") == 0 && i + 1 < argc) {
            if (parse_on_off(argv[++i], &cfg->tee_selftest_enabled) != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--async-debug-events") == 0 && i + 1 < argc) {
            if (parse_on_off(argv[++i], &cfg->async_debug_events) != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--ticket-debug-hashes") == 0 && i + 1 < argc) {
            if (parse_on_off(argv[++i], &cfg->ticket_debug_hashes) != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--ticket-plain-cap") == 0 && i + 1 < argc) {
            if (parse_size_t_value(argv[++i], &cfg->ticket_plain_cap) != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--debug-level") == 0 && i + 1 < argc) {
            if (parse_nonnegative_int(argv[++i], &cfg->debug_level) != 0 || cfg->debug_level > 4) {
                return -1;
            }
        } else {
            return -1;
        }
    }
    return 0;
}

static int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void sockaddr_to_str(const struct sockaddr_storage *ss, socklen_t len, char *buf, size_t buflen) {
    (void) len;
    void *addr_ptr = NULL;
    uint16_t port = 0;

    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *) ss;
        addr_ptr = (void *) &sin->sin_addr;
        port = ntohs(sin->sin_port);
    } else if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *) ss;
        addr_ptr = (void *) &sin6->sin6_addr;
        port = ntohs(sin6->sin6_port);
    }

    char ip[INET6_ADDRSTRLEN] = {0};
    if (addr_ptr && inet_ntop(ss->ss_family, addr_ptr, ip, sizeof(ip)) != NULL) {
        snprintf(buf, buflen, "%s:%u", ip, (unsigned) port);
    } else {
        snprintf(buf, buflen, "unknown");
    }
}

static const char *close_reason_str(close_reason_t reason) {
    switch (reason) {
        case CLOSE_REASON_PEER_CLOSED: return "peer_closed";
        case CLOSE_REASON_PEER_HANGUP: return "peer_hangup";
        case CLOSE_REASON_HANDSHAKE_FAILURE: return "handshake_failure";
        case CLOSE_REASON_HANDSHAKE_TIMEOUT: return "handshake_timeout";
        case CLOSE_REASON_IDLE_TIMEOUT: return "idle_timeout";
        case CLOSE_REASON_SSL_READ_FAILURE: return "ssl_read_failure";
        case CLOSE_REASON_SSL_WRITE_FAILURE: return "ssl_write_failure";
        case CLOSE_REASON_PAYLOAD_LIMIT: return "payload_limit";
        case CLOSE_REASON_SERVER_SHUTDOWN: return "server_shutdown";
        default: return "unspecified";
    }
}

static void account_want(server_ctx_t *srv, client_ctx_t *c, int ret) {
    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        c->want_read = true;
        c->want_write = false;
        srv->counters.want_read_returns++;
    } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        c->want_read = false;
        c->want_write = true;
        srv->counters.want_write_returns++;
    }
}

static void account_km_call(server_ctx_t *srv, uint64_t duration_us)
{
    srv->counters.km_call_duration_sum_us += duration_us;
    if (duration_us > srv->counters.km_call_duration_max_us) {
        srv->counters.km_call_duration_max_us = duration_us;
    }
}

static void log_last_km_error(server_ctx_t *srv,
                               const char *operation,
                               size_t input_len,
                               size_t output_cap)
{
    tee_km_last_error_t error;
    if (tee_km_get_last_error(&srv->tee_km, &error) != 0) {
        log_line(srv, true, "ERROR",
                 "tee_call_failed operation=%s input_len=%zu output_cap=%zu diagnostics=unavailable",
                 operation, input_len, output_cap);
        return;
    }

    log_line(srv, true, "ERROR",
             "tee_call_failed operation=%s command=%" PRIu32
             " result=0x%08" PRIx32 " result_name=%s origin=0x%08" PRIx32
             " origin_name=%s input_len=%zu output_cap=%zu",
             operation,
             error.command_id,
             error.result,
             tee_km_result_name(error.result),
             error.origin,
             tee_km_origin_name(error.origin),
             input_len,
             output_cap);
}

static void log_ticket_blob_hash(server_ctx_t *srv,
                                 const char *direction,
                                 const unsigned char *buf,
                                 size_t len)
{
    unsigned char digest[32];
    char hex[65];

    if (srv->cfg.log_mode != LOG_MODE_DEBUG ||
        !srv->cfg.ticket_debug_hashes ||
        !buf || len == 0) {
        return;
    }

    if (mbedtls_sha256(buf, len, digest, 0) != 0) {
        log_line(srv, true, "ERROR",
                 "ticket_blob_hash_failed direction=%s len=%zu",
                 direction, len);
        return;
    }

    for (size_t i = 0; i < sizeof(digest); ++i) {
        (void)snprintf(hex + (i * 2U), sizeof(hex) - (i * 2U), "%02x", digest[i]);
    }
    hex[64] = '\0';

    log_line(srv, true, "DEBUG",
             "ticket_blob direction=%s len=%zu sha256=%s",
             direction, len, hex);
    memset(digest, 0, sizeof(digest));
}

static int tee_km_roundtrip_selftest(server_ctx_t *srv)
{
    static const unsigned char input[] = "scenario-b-wrap-unwrap-selftest";
    unsigned char blob[256];
    unsigned char output[128];
    size_t blob_len = 0;
    size_t output_len = 0;
    uint64_t wrap_us = 0;
    uint64_t unwrap_us = 0;

    memset(blob, 0, sizeof(blob));
    memset(output, 0, sizeof(output));

    if (tee_km_wrap_session_state(&srv->tee_km,
                                  input,
                                  sizeof(input) - 1U,
                                  blob,
                                  sizeof(blob),
                                  &blob_len,
                                  &wrap_us) != 0) {
        srv->counters.km_selftest_failure++;
        log_last_km_error(srv, "selftest_wrap", sizeof(input) - 1U, sizeof(blob));
        return -1;
    }

    log_ticket_blob_hash(srv, "selftest_write", blob, blob_len);

    if (tee_km_unwrap_session_state(&srv->tee_km,
                                    blob,
                                    blob_len,
                                    output,
                                    sizeof(output),
                                    &output_len,
                                    &unwrap_us) != 0) {
        srv->counters.km_selftest_failure++;
        log_last_km_error(srv, "selftest_unwrap", blob_len, sizeof(output));
        return -1;
    }

    if (output_len != sizeof(input) - 1U ||
        memcmp(input, output, output_len) != 0) {
        srv->counters.km_selftest_failure++;
        log_line(srv, true, "ERROR",
                 "tee_km_selftest_failed reason=plaintext_mismatch expected_len=%zu actual_len=%zu",
                 sizeof(input) - 1U, output_len);
        return -1;
    }

    srv->counters.km_selftest_success++;
    log_line(srv, false, "INFO",
             "tee_km_selftest_ok blob_len=%zu wrap_us=%" PRIu64 " unwrap_us=%" PRIu64,
             blob_len, wrap_us, unwrap_us);

    memset(blob, 0, sizeof(blob));
    memset(output, 0, sizeof(output));
    return 0;
}

static int setup_tee_km(server_ctx_t *srv)
{
    uint64_t call_us = 0;

    if (tee_km_open(&srv->tee_km) != 0) {
        srv->counters.km_init_failure++;
        fprintf(stderr, "failed to open Scenario B key-management TA (%s)\n", TA_KEY_MGMT_UUID_STR);
        return -1;
    }
    srv->tee_km_initialized = true;

    if (tee_km_init_root(&srv->tee_km, &call_us) != 0) {
        srv->counters.km_init_failure++;
        fprintf(stderr, "failed to initialize Scenario B key-management TA\n");
        tee_km_close(&srv->tee_km);
        srv->tee_km_initialized = false;
        return -1;
    }
    account_km_call(srv, call_us);
    srv->counters.km_init_success++;

    if (srv->cfg.tee_selftest_enabled && tee_km_roundtrip_selftest(srv) != 0) {
        fprintf(stderr, "Scenario B key-management TA self-test failed\n");
        tee_km_close(&srv->tee_km);
        srv->tee_km_initialized = false;
        return -1;
    }

    if (tee_km_reset_stats(&srv->tee_km) != 0) {
        log_last_km_error(srv, "reset_stats", 0, 0);
        return -1;
    }
    return 0;
}

static void free_tee_km(server_ctx_t *srv)
{
    if (srv->tee_km_initialized) {
        tee_km_close(&srv->tee_km);
        srv->tee_km_initialized = false;
    }
    if (srv->ticket_plain_buf && srv->ticket_plain_cap > 0) {
        mbedtls_platform_zeroize(srv->ticket_plain_buf,
                                 srv->ticket_plain_cap);
    }
    free(srv->ticket_plain_buf);
    srv->ticket_plain_buf = NULL;
    srv->ticket_plain_cap = 0;
}

static void account_sign_call(server_ctx_t *srv, uint64_t duration_us) {
    srv->counters.sign_call_duration_sum_us += duration_us;
    if (duration_us > srv->counters.sign_call_duration_max_us) {
        srv->counters.sign_call_duration_max_us = duration_us;
    }
}

typedef struct {
    size_t len;
    unsigned char data[96];
} async_signature_t;

static int ecdsa_raw_rs_to_der(const unsigned char raw_rs[TEE_SIGN_ECDSA_P256_RAW_SIG_LEN],
                               async_signature_t *sig)
{
    int ret;
    mbedtls_mpi r;
    mbedtls_mpi s_mpi;
    unsigned char der[96];
    unsigned char *p = der + sizeof(der);
    size_t len = 0;

    if (!raw_rs || !sig) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s_mpi);

    ret = mbedtls_mpi_read_binary(&r, raw_rs, 32);
    if (ret != 0) {
        goto out;
    }
    ret = mbedtls_mpi_read_binary(&s_mpi, raw_rs + 32, 32);
    if (ret != 0) {
        goto out;
    }

    ret = mbedtls_asn1_write_mpi(&p, der, &s_mpi);
    if (ret < 0) {
        goto out;
    }
    len += (size_t)ret;

    ret = mbedtls_asn1_write_mpi(&p, der, &r);
    if (ret < 0) {
        goto out;
    }
    len += (size_t)ret;

    ret = mbedtls_asn1_write_len(&p, der, len);
    if (ret < 0) {
        goto out;
    }
    len += (size_t)ret;

    ret = mbedtls_asn1_write_tag(&p, der, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret < 0) {
        goto out;
    }
    len += (size_t)ret;

    if (len > sizeof(sig->data)) {
        ret = MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
        goto out;
    }

    memmove(sig->data, p, len);
    sig->len = len;
    ret = 0;

out:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s_mpi);
    return ret;
}

#if defined(MBEDTLS_SSL_ASYNC_PRIVATE)
static void async_signature_release(mbedtls_ssl_context *ssl,
                                    async_signature_t *sig)
{
    if (sig != NULL) {
        mbedtls_platform_zeroize(sig, sizeof(*sig));
        free(sig);
    }
    if (ssl != NULL) {
        mbedtls_ssl_set_async_operation_data(ssl, NULL);
    }
}

static int async_sign_start_cb(mbedtls_ssl_context *ssl,
                               mbedtls_x509_crt *cert,
                               mbedtls_md_type_t md_alg,
                               const unsigned char *hash,
                               size_t hash_len)
{
    server_ctx_t *srv = (server_ctx_t *)mbedtls_ssl_get_user_data_p(ssl);
    async_signature_t *sig = NULL;
    unsigned char raw_sig[TEE_SIGN_ECDSA_P256_RAW_SIG_LEN];
    size_t raw_sig_len = 0;
    uint64_t call_us = 0;
    int ret;

    if (!srv || !srv->tee_sign_initialized || !cert ||
        !mbedtls_pk_can_do(&cert->pk, MBEDTLS_PK_ECDSA)) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    memset(raw_sig, 0, sizeof(raw_sig));
    srv->counters.async_sign_start_calls++;
    srv->counters.sign_attempt++;

    if (srv->cfg.log_mode == LOG_MODE_DEBUG && srv->cfg.async_debug_events) {
        log_line(srv, true, "DEBUG",
                 "async_sign_start md_alg=%d hash_len=%zu",
                 (int)md_alg, hash_len);
    }

    if (md_alg != MBEDTLS_MD_SHA256 || !hash || hash_len != 32U) {
        srv->counters.sign_failure++;
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    sig = calloc(1, sizeof(*sig));
    if (!sig) {
        srv->counters.sign_failure++;
        return MBEDTLS_ERR_PK_ALLOC_FAILED;
    }

    ret = tee_sign_sign_digest(&srv->tee_sign,
                               hash,
                               hash_len,
                               raw_sig,
                               sizeof(raw_sig),
                               &raw_sig_len,
                               &call_us);
    account_sign_call(srv, call_us);
    if (ret != 0 || raw_sig_len != TEE_SIGN_ECDSA_P256_RAW_SIG_LEN) {
        tee_sign_error_t tee_err;
        if (tee_sign_get_last_error(&srv->tee_sign, &tee_err) == 0) {
            log_line(srv, true, "ERROR",
                     "tee_sign_failed command=%" PRIu32 " result=0x%08" PRIx32
                     " origin=0x%08" PRIx32 " raw_len=%zu",
                     tee_err.command, tee_err.result, tee_err.origin, raw_sig_len);
        }
        mbedtls_platform_zeroize(raw_sig, sizeof(raw_sig));
        async_signature_release(ssl, sig);
        srv->counters.sign_failure++;
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    ret = ecdsa_raw_rs_to_der(raw_sig, sig);
    mbedtls_platform_zeroize(raw_sig, sizeof(raw_sig));
    if (ret != 0) {
        async_signature_release(ssl, sig);
        srv->counters.sign_failure++;
        return ret;
    }

    mbedtls_ssl_set_async_operation_data(ssl, sig);
    srv->counters.sign_success++;

    if (srv->cfg.log_mode == LOG_MODE_DEBUG && srv->cfg.async_debug_events) {
        log_line(srv, true, "DEBUG",
                 "async_sign_ready der_len=%zu tee_call_us=%" PRIu64,
                 sig->len, call_us);
    }
    return 0;
}

static int async_resume_cb(mbedtls_ssl_context *ssl,
                           unsigned char *output,
                           size_t *output_len,
                           size_t output_size)
{
    server_ctx_t *srv = (server_ctx_t *)mbedtls_ssl_get_user_data_p(ssl);
    async_signature_t *sig =
        (async_signature_t *)mbedtls_ssl_get_async_operation_data(ssl);

    if (srv) {
        srv->counters.async_resume_calls++;
    }

    if (!sig || !output || !output_len) {
        if (srv) {
            log_line(srv, true, "ERROR",
                     "async_resume_invalid_state signature=%s output=%s output_len=%s",
                     sig ? "present" : "missing",
                     output ? "present" : "missing",
                     output_len ? "present" : "missing");
        }
        async_signature_release(ssl, sig);
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
    if (sig->len > output_size) {
        if (srv) {
            log_line(srv, true, "ERROR",
                     "async_resume_short_buffer signature_len=%zu output_size=%zu",
                     sig->len, output_size);
        }
        async_signature_release(ssl, sig);
        return MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
    }

    memcpy(output, sig->data, sig->len);
    *output_len = sig->len;

    if (srv && srv->cfg.log_mode == LOG_MODE_DEBUG && srv->cfg.async_debug_events) {
        log_line(srv, true, "DEBUG", "async_resume signature_len=%zu", sig->len);
    }

    async_signature_release(ssl, sig);
    return 0;
}

static void async_cancel_cb(mbedtls_ssl_context *ssl)
{
    server_ctx_t *srv = (server_ctx_t *)mbedtls_ssl_get_user_data_p(ssl);
    async_signature_t *sig = (async_signature_t *)mbedtls_ssl_get_async_operation_data(ssl);

    if (srv) {
        srv->counters.async_cancel_calls++;
    }

    if (srv && srv->cfg.log_mode == LOG_MODE_DEBUG && srv->cfg.async_debug_events) {
        log_line(srv, true, "DEBUG", "async_cancel pending_signature=%s",
                 sig != NULL ? "yes" : "no");
    }

    async_signature_release(ssl, sig);
}
#endif /* MBEDTLS_SSL_ASYNC_PRIVATE */

static int export_p256_key_material(mbedtls_pk_context *pk,
                                    unsigned char key_blob[TEE_SIGN_P256_KEY_BLOB_LEN])
{
    mbedtls_ecp_keypair *ec;
    unsigned char d[32];
    unsigned char q[65];
    size_t d_len = 0;
    size_t q_len = 0;
    int ret;

    if (!pk || !key_blob || mbedtls_pk_get_type(pk) != MBEDTLS_PK_ECKEY) {
        return -1;
    }

    ec = mbedtls_pk_ec(*pk);
    if (!ec) {
        return -1;
    }

    /* Use public Mbed TLS 3.6 ECP accessors instead of relying on private
     * structure fields. This is a provisioning-only step: the key material is
     * imported into the TA at startup, while TLS handshakes use the async
     * private-key callback and do not sign with the normal-world key.
     */
    if (mbedtls_ecp_keypair_get_group_id(ec) != MBEDTLS_ECP_DP_SECP256R1) {
        return -1;
    }

    ret = mbedtls_ecp_write_key_ext(ec, &d_len, d, sizeof(d));
    if (ret != 0 || d_len != 32U) {
        return -1;
    }

    ret = mbedtls_ecp_write_public_key(ec,
                                       MBEDTLS_ECP_PF_UNCOMPRESSED,
                                       &q_len,
                                       q,
                                       sizeof(q));
    if (ret != 0 || q_len != 65U || q[0] != 0x04U) {
        mbedtls_platform_zeroize(d, sizeof(d));
        return -1;
    }

    memcpy(key_blob, d, 32U);
    memcpy(key_blob + 32U, q + 1U, 32U);
    memcpy(key_blob + 64U, q + 33U, 32U);

    mbedtls_platform_zeroize(d, sizeof(d));
    mbedtls_platform_zeroize(q, sizeof(q));
    return 0;
}

static int tee_sign_roundtrip_selftest(server_ctx_t *srv)
{
    static const unsigned char digest[TEE_SIGN_SHA256_DIGEST_LEN] = {
        0x4d, 0x30, 0x2d, 0x53, 0x63, 0x65, 0x6e, 0x61,
        0x72, 0x69, 0x6f, 0x2d, 0x43, 0x2d, 0x54, 0x45,
        0x45, 0x2d, 0x53, 0x69, 0x67, 0x6e, 0x2d, 0x54,
        0x65, 0x73, 0x74, 0x2d, 0x30, 0x30, 0x30, 0x31
    };
    unsigned char raw_sig[TEE_SIGN_ECDSA_P256_RAW_SIG_LEN];
    async_signature_t der_sig;
    size_t raw_sig_len = 0;
    uint64_t call_us = 0;
    int ret;

    memset(raw_sig, 0, sizeof(raw_sig));
    memset(&der_sig, 0, sizeof(der_sig));

    ret = tee_sign_sign_digest(&srv->tee_sign,
                               digest,
                               sizeof(digest),
                               raw_sig,
                               sizeof(raw_sig),
                               &raw_sig_len,
                               &call_us);
    account_sign_call(srv, call_us);
    if (ret != 0 || raw_sig_len != sizeof(raw_sig)) {
        tee_sign_error_t tee_err;
        if (tee_sign_get_last_error(&srv->tee_sign, &tee_err) == 0) {
            log_line(srv, false, "ERROR",
                     "tee_sign_selftest_call_failed command=%" PRIu32
                     " result=0x%08" PRIx32 " origin=0x%08" PRIx32,
                     tee_err.command, tee_err.result, tee_err.origin);
        }
        mbedtls_platform_zeroize(raw_sig, sizeof(raw_sig));
        srv->counters.sign_selftest_failure++;
        return -1;
    }

    ret = ecdsa_raw_rs_to_der(raw_sig, &der_sig);
    mbedtls_platform_zeroize(raw_sig, sizeof(raw_sig));
    if (ret != 0) {
        srv->counters.sign_selftest_failure++;
        return -1;
    }

    ret = mbedtls_pk_verify(&srv->cert.pk,
                            MBEDTLS_MD_SHA256,
                            digest,
                            sizeof(digest),
                            der_sig.data,
                            der_sig.len);
    mbedtls_platform_zeroize(&der_sig, sizeof(der_sig));
    if (ret != 0) {
        char errbuf[256];
        format_mbedtls_error(ret, errbuf, sizeof(errbuf));
        log_line(srv, false, "ERROR",
                 "tee_sign_selftest_verify_failed ret=%d hex=-0x%04x err=%s",
                 ret, (unsigned int)(-ret), errbuf);
        srv->counters.sign_selftest_failure++;
        return -1;
    }

    srv->counters.sign_selftest_success++;
    log_line(srv, false, "INFO",
             "tee_sign_selftest_ok signature=ecdsa_p256 digest=sha256 tee_call_us=%" PRIu64,
             call_us);
    return 0;
}

static int setup_tee_signer_from_key(server_ctx_t *srv)
{
    unsigned char key_blob[TEE_SIGN_P256_KEY_BLOB_LEN];
    uint64_t call_us = 0;
    int rc;

    memset(key_blob, 0, sizeof(key_blob));
    srv->counters.sign_import_attempt++;

    if (export_p256_key_material(&srv->pkey, key_blob) != 0) {
        srv->counters.sign_import_failure++;
        fprintf(stderr, "failed to export ECDSA P-256 key material for TA provisioning\n");
        return -1;
    }

    if (tee_sign_open(&srv->tee_sign) != 0) {
        mbedtls_platform_zeroize(key_blob, sizeof(key_blob));
        srv->counters.sign_init_failure++;
        fprintf(stderr, "failed to open Scenario C private-key TA uuid=%s\n", TA_PRIVKEY_SIGN_UUID_STR);
        return -1;
    }
    srv->tee_sign_initialized = true;
    srv->counters.sign_init_success++;

    rc = tee_sign_import_p256_key(&srv->tee_sign, key_blob, sizeof(key_blob), &call_us);
    account_sign_call(srv, call_us);
    mbedtls_platform_zeroize(key_blob, sizeof(key_blob));
    if (rc != 0) {
        tee_sign_error_t tee_err;
        srv->counters.sign_import_failure++;
        if (tee_sign_get_last_error(&srv->tee_sign, &tee_err) == 0) {
            fprintf(stderr,
                    "failed to import ECDSA P-256 key into Scenario C TA: "
                    "command=%" PRIu32 " result=0x%08" PRIx32
                    " origin=0x%08" PRIx32 "\n",
                    tee_err.command, tee_err.result, tee_err.origin);
        } else {
            fprintf(stderr, "failed to import ECDSA P-256 key into Scenario C TA\n");
        }
        return -1;
    }
    srv->counters.sign_import_success++;

    if (srv->cfg.tee_selftest_enabled && tee_sign_roundtrip_selftest(srv) != 0) {
        fprintf(stderr, "Scenario C private-key TA self-test failed\n");
        return -1;
    }

    if (tee_sign_reset_stats(&srv->tee_sign) != 0) {
        fprintf(stderr, "warning: failed to reset Scenario C TA statistics after provisioning\n");
    }

    /* Runtime signing statistics exclude one-time provisioning and self-test. */
    srv->counters.sign_call_duration_sum_us = 0;
    srv->counters.sign_call_duration_max_us = 0;
    return 0;
}

static void free_tee_signer(server_ctx_t *srv)
{
    if (srv->tee_sign_initialized) {
        tee_sign_close(&srv->tee_sign);
        srv->tee_sign_initialized = false;
    }
}


static int ticket_write_cb(void *p_ticket, const mbedtls_ssl_session *session,
                           unsigned char *start, const unsigned char *end,
                           size_t *tlen, uint32_t *lifetime)
{
    server_ctx_t *srv = (server_ctx_t *)p_ticket;

    srv->counters.ticket_write_attempt++;

    if (!srv->cfg.tee_ticket_protection_enabled) {
        int ret = mbedtls_ssl_ticket_write(&srv->ticket_ctx,
                                           session,
                                           start,
                                           end,
                                           tlen,
                                           lifetime);
        if (ret == 0) {
            srv->counters.ticket_write_success++;
        } else {
            srv->counters.ticket_write_failure++;
        }
        return ret;
    }

    size_t plain_len = 0;
    size_t blob_len = 0;
    uint64_t call_us = 0;

    srv->counters.km_wrap_attempt++;

    if (!srv->tee_km_initialized || !srv->ticket_plain_buf ||
        srv->ticket_plain_cap == 0 || end <= start) {
        srv->counters.ticket_write_failure++;
        srv->counters.km_wrap_failure++;
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    int ret = mbedtls_ssl_session_save(session,
                                       srv->ticket_plain_buf,
                                       srv->ticket_plain_cap,
                                       &plain_len);
    if (ret != 0) {
        srv->counters.ticket_write_failure++;
        srv->counters.km_wrap_failure++;
        return ret;
    }

    if (tee_km_wrap_session_state(&srv->tee_km,
                                  srv->ticket_plain_buf,
                                  plain_len,
                                  start,
                                  (size_t)(end - start),
                                  &blob_len,
                                  &call_us) != 0) {
        srv->counters.ticket_write_failure++;
        srv->counters.km_wrap_failure++;
        log_last_km_error(srv,
                          "wrap_session_state",
                          plain_len,
                          (size_t)(end - start));
        mbedtls_platform_zeroize(srv->ticket_plain_buf,
                                 srv->ticket_plain_cap);
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    account_km_call(srv, call_us);
    log_ticket_blob_hash(srv, "write", start, blob_len);
    mbedtls_platform_zeroize(srv->ticket_plain_buf, srv->ticket_plain_cap);

    *tlen = blob_len;
    *lifetime = (uint32_t)srv->cfg.ticket_lifetime_sec;
    srv->counters.ticket_write_success++;
    srv->counters.km_wrap_success++;
    return 0;
}

static int ticket_parse_cb(void *p_ticket, mbedtls_ssl_session *session,
                           unsigned char *buf, size_t len)
{
    server_ctx_t *srv = (server_ctx_t *)p_ticket;

    srv->counters.ticket_parse_attempt++;

    if (!srv->cfg.tee_ticket_protection_enabled) {
        int ret = mbedtls_ssl_ticket_parse(&srv->ticket_ctx,
                                           session,
                                           buf,
                                           len);
        if (ret == 0) {
            srv->counters.ticket_parse_success++;
        } else {
            srv->counters.ticket_parse_failure++;
        }
        return ret;
    }

    size_t plain_len = 0;
    uint64_t call_us = 0;

    srv->counters.km_unwrap_attempt++;

    if (!srv->tee_km_initialized || !srv->ticket_plain_buf ||
        srv->ticket_plain_cap == 0 || !buf || len == 0) {
        srv->counters.ticket_parse_failure++;
        srv->counters.km_unwrap_failure++;
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    log_ticket_blob_hash(srv, "parse", buf, len);

    if (tee_km_unwrap_session_state(&srv->tee_km,
                                    buf,
                                    len,
                                    srv->ticket_plain_buf,
                                    srv->ticket_plain_cap,
                                    &plain_len,
                                    &call_us) != 0) {
        srv->counters.ticket_parse_failure++;
        srv->counters.km_unwrap_failure++;
        log_last_km_error(srv,
                          "unwrap_session_state",
                          len,
                          srv->ticket_plain_cap);
        mbedtls_platform_zeroize(srv->ticket_plain_buf,
                                 srv->ticket_plain_cap);
        return MBEDTLS_ERR_SSL_INVALID_MAC;
    }

    account_km_call(srv, call_us);
    int ret = mbedtls_ssl_session_load(session,
                                       srv->ticket_plain_buf,
                                       plain_len);
    mbedtls_platform_zeroize(srv->ticket_plain_buf,
                             srv->ticket_plain_cap);
    if (ret != 0) {
        char errbuf[256];
        format_mbedtls_error(ret, errbuf, sizeof(errbuf));
        srv->counters.ticket_parse_failure++;
        srv->counters.km_unwrap_failure++;
        log_line(srv, true, "ERROR",
                 "ticket_session_load_failed ret=%d hex=-0x%04x "
                 "plain_len=%zu err=%s",
                 ret,
                 (unsigned int)(-ret),
                 plain_len,
                 errbuf);
        return ret;
    }

    srv->counters.ticket_parse_success++;
    srv->counters.km_unwrap_success++;
    return 0;
}

static int validate_certificate_profile(server_ctx_t *srv) {
    int ret;
    char errbuf[256];

    if (!srv->cfg.strict_cert_profile) {
        return 0;
    }

    if (!mbedtls_pk_can_do(&srv->pkey, MBEDTLS_PK_ECDSA)) {
        fprintf(stderr, "strict certificate profile failed: private key is not ECDSA-capable\n");
        return -1;
    }

    if (!mbedtls_pk_can_do(&srv->cert.pk, MBEDTLS_PK_ECDSA)) {
        fprintf(stderr, "strict certificate profile failed: certificate public key is not ECDSA-capable\n");
        return -1;
    }

    ret = mbedtls_pk_check_pair(&srv->cert.pk, &srv->pkey,
                                mbedtls_ctr_drbg_random, &srv->ctr_drbg);
    if (ret != 0) {
        format_mbedtls_error(ret, errbuf, sizeof(errbuf));
        fprintf(stderr, "strict certificate profile failed: cert/key pair mismatch: %s\n", errbuf);
        return -1;
    }

    /*
     * Curve-specific enforcement is primarily performed by the TLS profile:
     * only ecdsa_secp256r1_sha256 and secp256r1 are configured. A non-P-256
     * ECDSA certificate/key will therefore not complete the intended TLS 1.3
     * handshake. This avoids relying on Mbed TLS private struct fields here.
     */
    return 0;
}


typedef struct {
    uint32_t tee_connection_handle;
} scenario_d_backend_connection_t;

typedef struct {
    uint32_t tee_transform_handle;
} scenario_d_backend_transform_t;

static void log_tee_client_error(server_ctx_t *srv,
                                 const char *operation)
{
    tee_tls_d_error_t error;
    if (tee_tls_d_get_last_error(&srv->tee_client, &error) == 0) {
        log_line(srv, true, "ERROR",
                 "%s command=%" PRIu32 " result=0x%08" PRIx32
                 " origin=0x%08" PRIx32,
                 operation,
                 error.command,
                 error.result,
                 error.origin);
    }
}

static int scenario_d_backend_connection_init(
    mbedtls_ssl_context *ssl,
    void *config_data,
    void **connection_data)
{
    server_ctx_t *srv = (server_ctx_t *) config_data;
    scenario_d_backend_connection_t *backend_connection;
    uint32_t tee_handle = 0;
    uint64_t duration_us = 0;

    (void) ssl;

    if (srv == NULL || connection_data == NULL ||
        !srv->tee_client_initialized) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    *connection_data = NULL;
    backend_connection = calloc(1, sizeof(*backend_connection));
    if (backend_connection == NULL) {
        srv->counters.backend_connection_init_failure++;
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }

    if (tee_tls_d_connection_open(&srv->tee_client,
                                  &tee_handle,
                                  &duration_us) != 0) {
        srv->counters.backend_connection_init_failure++;
        srv->counters.tee_connection_open_failure++;
        log_tee_client_error(srv, "tee_connection_open_failed");
        free(backend_connection);
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    backend_connection->tee_connection_handle = tee_handle;
    *connection_data = backend_connection;
    srv->counters.backend_connection_init_success++;
    srv->counters.tee_connection_open_success++;

    log_line(srv, true, "DEBUG",
             "d4_backend_connection_init tee_handle=%" PRIu32
             " tee_call_us=%" PRIu64,
             tee_handle,
             duration_us);
    return 0;
}

static void scenario_d_backend_connection_free(
    mbedtls_ssl_context *ssl,
    void *config_data,
    void *connection_data)
{
    server_ctx_t *srv = (server_ctx_t *) config_data;
    scenario_d_backend_connection_t *backend_connection =
        (scenario_d_backend_connection_t *) connection_data;
    uint64_t duration_us = 0;

    (void) ssl;

    if (srv == NULL) {
        free(backend_connection);
        return;
    }

    srv->counters.backend_connection_free_calls++;

    if (backend_connection == NULL) {
        log_line(srv, true, "ERROR",
                 "d4_backend_connection_free missing_connection_data");
        return;
    }

    if (tee_tls_d_connection_close(
            &srv->tee_client,
            backend_connection->tee_connection_handle,
            &duration_us) != 0) {
        srv->counters.tee_connection_close_failure++;
        log_tee_client_error(srv, "tee_connection_close_failed");
    } else {
        srv->counters.tee_connection_close_success++;
        log_line(srv, true, "DEBUG",
                 "d4_backend_connection_free tee_handle=%" PRIu32
                 " tee_call_us=%" PRIu64,
                 backend_connection->tee_connection_handle,
                 duration_us);
    }

    memset(backend_connection, 0, sizeof(*backend_connection));
    free(backend_connection);
}

static void scenario_d_backend_transform_free(
    void *config_data,
    void *connection_data,
    void *transform_data)
{
    server_ctx_t *srv = (server_ctx_t *) config_data;
    scenario_d_backend_transform_t *backend_transform =
        (scenario_d_backend_transform_t *) transform_data;
    uint64_t duration_us = 0;

    (void) connection_data;

    if (srv != NULL) {
        srv->counters.backend_transform_free_calls++;
    }

    if (srv != NULL && backend_transform != NULL &&
        backend_transform->tee_transform_handle != 0) {
        if (tee_tls_d_transform_free(
                &srv->tee_client,
                backend_transform->tee_transform_handle,
                &duration_us) != 0) {
            srv->counters.tee_transform_free_failure++;
            log_tee_client_error(srv, "tee_transform_free_failed");
        } else {
            srv->counters.tee_transform_free_success++;
            log_line(srv, true, "DEBUG",
                     "d4_backend_transform_free tee_transform=%" PRIu32
                     " tee_call_us=%" PRIu64,
                     backend_transform->tee_transform_handle,
                     duration_us);
        }
    }

    if (backend_transform != NULL) {
        memset(backend_transform, 0, sizeof(*backend_transform));
        free(backend_transform);
    }
}

static int scenario_d_backend_transform_import(
    mbedtls_ssl_context *ssl,
    void *config_data,
    void *connection_data,
    uint16_t ciphersuite,
    uint16_t tls_version,
    size_t tag_len,
    const unsigned char *key_enc,
    size_t key_enc_len,
    const unsigned char *iv_enc,
    size_t iv_enc_len,
    const unsigned char *key_dec,
    size_t key_dec_len,
    const unsigned char *iv_dec,
    size_t iv_dec_len,
    void **transform_data)
{
    server_ctx_t *srv = (server_ctx_t *) config_data;
    scenario_d_backend_connection_t *backend_connection =
        (scenario_d_backend_connection_t *) connection_data;
    scenario_d_backend_transform_t *backend_transform;
    tee_tls_d_transform_params_t params;
    uint32_t tee_transform = 0;
    uint64_t duration_us = 0;

    (void) ssl;

    if (srv == NULL || backend_connection == NULL ||
        transform_data == NULL || backend_connection->tee_connection_handle == 0) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    *transform_data = NULL;
    backend_transform = calloc(1, sizeof(*backend_transform));
    if (backend_transform == NULL) {
        srv->counters.backend_transform_import_failure++;
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }

    memset(&params, 0, sizeof(params));
    params.connection_handle = backend_connection->tee_connection_handle;
    params.ciphersuite = ciphersuite;
    params.tls_version = tls_version;
    params.tag_len = tag_len;
    params.key_enc = key_enc;
    params.key_enc_len = key_enc_len;
    params.iv_enc = iv_enc;
    params.iv_enc_len = iv_enc_len;
    params.key_dec = key_dec;
    params.key_dec_len = key_dec_len;
    params.iv_dec = iv_dec;
    params.iv_dec_len = iv_dec_len;

    if (tee_tls_d_transform_import(&srv->tee_client,
                                   &params,
                                   &tee_transform,
                                   &duration_us) != 0) {
        srv->counters.backend_transform_import_failure++;
        srv->counters.tee_transform_import_failure++;
        log_tee_client_error(srv, "tee_transform_import_failed");
        free(backend_transform);
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    backend_transform->tee_transform_handle = tee_transform;
    *transform_data = backend_transform;
    srv->counters.backend_transform_import_success++;
    srv->counters.tee_transform_import_success++;
    log_line(srv, true, "DEBUG",
             "d4_backend_transform_import tee_connection=%" PRIu32
             " tee_transform=%" PRIu32 " key_len=%zu iv_len=%zu tag_len=%zu"
             " tee_call_us=%" PRIu64,
             backend_connection->tee_connection_handle,
             tee_transform,
             key_enc_len,
             iv_enc_len,
             tag_len,
             duration_us);
    return 0;
}



static int scenario_d_backend_server_key_share(
    mbedtls_ssl_context *ssl,
    void *config_data,
    void *connection_data,
    uint16_t named_group,
    unsigned char *public_key,
    size_t public_key_size,
    size_t *public_key_len)
{
    server_ctx_t *srv = (server_ctx_t *) config_data;
    scenario_d_backend_connection_t *backend_connection =
        (scenario_d_backend_connection_t *) connection_data;
    tee_tls_d_server_key_share_params_t params;
    uint64_t duration_us = 0;

    (void) ssl;

    if (srv == NULL || backend_connection == NULL || public_key == NULL ||
        public_key_len == NULL || backend_connection->tee_connection_handle == 0) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    memset(&params, 0, sizeof(params));
    params.connection_handle = backend_connection->tee_connection_handle;
    params.named_group = named_group;
    params.public_key = public_key;
    params.public_key_size = public_key_size;
    params.public_key_len = public_key_len;

    if (tee_tls_d_server_key_share(&srv->tee_client,
                                   &params,
                                   &duration_us) != 0) {
        srv->counters.backend_server_key_share_failure++;
        srv->counters.tee_server_key_share_failure++;
        log_tee_client_error(srv, "tee_server_key_share_failed");
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    srv->counters.backend_server_key_share_success++;
    srv->counters.tee_server_key_share_success++;
    log_line(srv, true, "DEBUG",
             "d4_backend_server_key_share tee_connection=%" PRIu32
             " named_group=0x%04" PRIx16 " public_key_len=%zu"
             " tee_call_us=%" PRIu64,
             backend_connection->tee_connection_handle,
             named_group,
             *public_key_len,
             duration_us);
    return 0;
}

static int scenario_d_backend_handshake_keys(
    mbedtls_ssl_context *ssl,
    void *config_data,
    void *connection_data,
    uint16_t ciphersuite,
    uint16_t tls_version,
    const unsigned char *psk,
    size_t psk_len,
    int psk_type,
    const unsigned char *shared_secret,
    size_t shared_secret_len,
    const unsigned char *peer_public_key,
    size_t peer_public_key_len,
    const unsigned char *transcript,
    size_t transcript_len,
    void **transform_data)
{
    server_ctx_t *srv = (server_ctx_t *) config_data;
    scenario_d_backend_connection_t *backend_connection =
        (scenario_d_backend_connection_t *) connection_data;
    scenario_d_backend_transform_t *backend_transform;
    tee_tls_d_handshake_keys_params_t params;
    uint32_t tee_transform = 0;
    uint64_t duration_us = 0;

    (void) ssl;

    if (srv == NULL || backend_connection == NULL || transform_data == NULL ||
        backend_connection->tee_connection_handle == 0) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    *transform_data = NULL;
    backend_transform = calloc(1, sizeof(*backend_transform));
    if (backend_transform == NULL) {
        srv->counters.backend_handshake_keys_failure++;
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }

    memset(&params, 0, sizeof(params));
    params.connection_handle = backend_connection->tee_connection_handle;
    params.ciphersuite = ciphersuite;
    params.tls_version = tls_version;
    params.psk = psk;
    params.psk_len = psk_len;
    params.psk_type = psk_type;
    params.shared_secret = shared_secret;
    params.shared_secret_len = shared_secret_len;
    params.peer_public_key = peer_public_key;
    params.peer_public_key_len = peer_public_key_len;
    params.transcript = transcript;
    params.transcript_len = transcript_len;

    if (tee_tls_d_handshake_keys(&srv->tee_client,
                                 &params,
                                 &tee_transform,
                                 &duration_us) != 0) {
        srv->counters.backend_handshake_keys_failure++;
        srv->counters.tee_handshake_keys_failure++;
        log_tee_client_error(srv, "tee_handshake_keys_failed");
        free(backend_transform);
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    backend_transform->tee_transform_handle = tee_transform;
    *transform_data = backend_transform;
    srv->counters.backend_handshake_keys_success++;
    srv->counters.tee_handshake_keys_success++;
    log_line(srv, true, "DEBUG",
             "d4_backend_handshake_keys tee_connection=%" PRIu32
             " tee_transform=%" PRIu32 " psk_len=%zu shared_secret_len=%zu"
             " peer_public_key_len=%zu transcript_len=%zu tee_call_us=%" PRIu64,
             backend_connection->tee_connection_handle,
             tee_transform,
             psk_len,
             shared_secret_len,
             peer_public_key_len,
             transcript_len,
             duration_us);
    return 0;
}

static int scenario_d_backend_application_keys(
    mbedtls_ssl_context *ssl,
    void *config_data,
    void *connection_data,
    uint16_t ciphersuite,
    uint16_t tls_version,
    const unsigned char *transcript,
    size_t transcript_len,
    void **transform_data)
{
    server_ctx_t *srv = (server_ctx_t *) config_data;
    scenario_d_backend_connection_t *backend_connection =
        (scenario_d_backend_connection_t *) connection_data;
    scenario_d_backend_transform_t *backend_transform;
    tee_tls_d_application_keys_params_t params;
    uint32_t tee_transform = 0;
    uint64_t duration_us = 0;

    (void) ssl;

    if (srv == NULL || backend_connection == NULL || transform_data == NULL ||
        backend_connection->tee_connection_handle == 0) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    *transform_data = NULL;
    backend_transform = calloc(1, sizeof(*backend_transform));
    if (backend_transform == NULL) {
        srv->counters.backend_application_keys_failure++;
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }

    memset(&params, 0, sizeof(params));
    params.connection_handle = backend_connection->tee_connection_handle;
    params.ciphersuite = ciphersuite;
    params.tls_version = tls_version;
    params.transcript = transcript;
    params.transcript_len = transcript_len;

    if (tee_tls_d_application_keys(&srv->tee_client,
                                   &params,
                                   &tee_transform,
                                   &duration_us) != 0) {
        srv->counters.backend_application_keys_failure++;
        srv->counters.tee_application_keys_failure++;
        log_tee_client_error(srv, "tee_application_keys_failed");
        free(backend_transform);
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    backend_transform->tee_transform_handle = tee_transform;
    *transform_data = backend_transform;
    srv->counters.backend_application_keys_success++;
    srv->counters.tee_application_keys_success++;
    log_line(srv, true, "DEBUG",
             "d4_backend_application_keys tee_connection=%" PRIu32
             " tee_transform=%" PRIu32 " transcript_len=%zu"
             " tee_call_us=%" PRIu64,
             backend_connection->tee_connection_handle,
             tee_transform,
             transcript_len,
             duration_us);
    return 0;
}

static int scenario_d_backend_finished(
    mbedtls_ssl_context *ssl,
    void *config_data,
    void *connection_data,
    int from,
    const unsigned char *transcript,
    size_t transcript_len,
    unsigned char *verify_data,
    size_t verify_data_size,
    size_t *verify_data_len)
{
    server_ctx_t *srv = (server_ctx_t *) config_data;
    scenario_d_backend_connection_t *backend_connection =
        (scenario_d_backend_connection_t *) connection_data;
    tee_tls_d_finished_params_t params;
    uint64_t duration_us = 0;

    (void) ssl;

    if (srv == NULL || backend_connection == NULL ||
        backend_connection->tee_connection_handle == 0) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    memset(&params, 0, sizeof(params));
    params.connection_handle = backend_connection->tee_connection_handle;
    params.from = from;
    params.transcript = transcript;
    params.transcript_len = transcript_len;
    params.verify_data = verify_data;
    params.verify_data_size = verify_data_size;
    params.verify_data_len = verify_data_len;

    if (tee_tls_d_finished(&srv->tee_client,
                           &params,
                           &duration_us) != 0) {
        srv->counters.finished_failure++;
        srv->counters.tee_finished_failure++;
        log_tee_client_error(srv, "tee_finished_failed");
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    srv->counters.finished_success++;
    srv->counters.tee_finished_success++;
    log_line(srv, true, "DEBUG",
             "d4_backend_finished from=%d transcript_len=%zu"
             " verify_len=%zu tee_call_us=%" PRIu64,
             from,
             transcript_len,
             verify_data_len != NULL ? *verify_data_len : 0,
             duration_us);
    return 0;
}

static int scenario_d_backend_resumption_master(
    mbedtls_ssl_context *ssl,
    void *config_data,
    void *connection_data,
    uint16_t ciphersuite,
    uint16_t tls_version,
    const unsigned char *transcript,
    size_t transcript_len,
    unsigned char *resumption_master,
    size_t resumption_master_size,
    size_t *resumption_master_len)
{
    server_ctx_t *srv = (server_ctx_t *) config_data;
    scenario_d_backend_connection_t *backend_connection =
        (scenario_d_backend_connection_t *) connection_data;
    tee_tls_d_resumption_master_params_t params;
    uint64_t duration_us = 0;

    (void) ssl;

    if (srv == NULL || backend_connection == NULL || transcript == NULL ||
        resumption_master == NULL || resumption_master_len == NULL ||
        backend_connection->tee_connection_handle == 0) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    memset(&params, 0, sizeof(params));
    params.connection_handle = backend_connection->tee_connection_handle;
    params.ciphersuite = ciphersuite;
    params.tls_version = tls_version;
    params.transcript = transcript;
    params.transcript_len = transcript_len;
    params.resumption_master = resumption_master;
    params.resumption_master_size = resumption_master_size;
    params.resumption_master_len = resumption_master_len;

    if (tee_tls_d_resumption_master(&srv->tee_client,
                                    &params,
                                    &duration_us) != 0) {
        srv->counters.backend_resumption_master_failure++;
        srv->counters.tee_resumption_master_failure++;
        log_tee_client_error(srv, "tee_resumption_master_failed");
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    srv->counters.backend_resumption_master_success++;
    srv->counters.tee_resumption_master_success++;
    log_line(srv, true, "DEBUG",
             "d4_backend_resumption_master tee_connection=%" PRIu32
             " transcript_len=%zu rms_len=%zu tee_call_us=%" PRIu64,
             backend_connection->tee_connection_handle,
             transcript_len,
             *resumption_master_len,
             duration_us);
    return 0;
}

static int scenario_d_backend_resumption_psk(
    mbedtls_ssl_context *ssl,
    void *config_data,
    void *connection_data,
    uint16_t ciphersuite,
    uint16_t tls_version,
    const unsigned char *ticket_nonce,
    size_t ticket_nonce_len,
    unsigned char *resumption_psk,
    size_t resumption_psk_size,
    size_t *resumption_psk_len)
{
    server_ctx_t *srv = (server_ctx_t *) config_data;
    scenario_d_backend_connection_t *backend_connection =
        (scenario_d_backend_connection_t *) connection_data;
    tee_tls_d_resumption_psk_params_t params;
    uint64_t duration_us = 0;

    (void) ssl;

    if (srv == NULL || backend_connection == NULL || ticket_nonce == NULL ||
        resumption_psk == NULL || resumption_psk_len == NULL ||
        backend_connection->tee_connection_handle == 0) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    memset(&params, 0, sizeof(params));
    params.connection_handle = backend_connection->tee_connection_handle;
    params.ciphersuite = ciphersuite;
    params.tls_version = tls_version;
    params.ticket_nonce = ticket_nonce;
    params.ticket_nonce_len = ticket_nonce_len;
    params.resumption_psk = resumption_psk;
    params.resumption_psk_size = resumption_psk_size;
    params.resumption_psk_len = resumption_psk_len;

    if (tee_tls_d_resumption_psk(&srv->tee_client,
                                 &params,
                                 &duration_us) != 0) {
        srv->counters.backend_resumption_psk_failure++;
        srv->counters.tee_resumption_psk_failure++;
        log_tee_client_error(srv, "tee_resumption_psk_failed");
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    srv->counters.backend_resumption_psk_success++;
    srv->counters.tee_resumption_psk_success++;
    log_line(srv, true, "DEBUG",
             "d4_backend_resumption_psk tee_connection=%" PRIu32
             " ticket_nonce_len=%zu psk_len=%zu tee_call_us=%" PRIu64,
             backend_connection->tee_connection_handle,
             ticket_nonce_len,
             *resumption_psk_len,
             duration_us);
    return 0;
}

static int scenario_d_backend_record_seal(
    mbedtls_ssl_context *ssl,
    void *config_data,
    void *connection_data,
    void *transform_data,
    const unsigned char *aad,
    size_t aad_len,
    const unsigned char *plaintext,
    size_t plaintext_len,
    unsigned char *ciphertext,
    size_t ciphertext_size,
    size_t *ciphertext_len)
{
    server_ctx_t *srv = (server_ctx_t *) config_data;
    scenario_d_backend_transform_t *backend_transform =
        (scenario_d_backend_transform_t *) transform_data;
    uint64_t duration_us = 0;

    (void) ssl;
    (void) connection_data;

    if (srv == NULL || backend_transform == NULL ||
        backend_transform->tee_transform_handle == 0) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    if (tee_tls_d_record_seal(&srv->tee_client,
                              backend_transform->tee_transform_handle,
                              aad, aad_len,
                              plaintext, plaintext_len,
                              ciphertext, ciphertext_size,
                              ciphertext_len,
                              &duration_us) != 0) {
        srv->counters.record_seal_failure++;
        log_tee_client_error(srv, "tee_record_seal_failed");
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    srv->counters.record_seal_success++;
    return 0;
}

static int scenario_d_backend_record_open(
    mbedtls_ssl_context *ssl,
    void *config_data,
    void *connection_data,
    void *transform_data,
    const unsigned char *aad,
    size_t aad_len,
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    unsigned char *plaintext,
    size_t plaintext_size,
    size_t *plaintext_len)
{
    server_ctx_t *srv = (server_ctx_t *) config_data;
    scenario_d_backend_transform_t *backend_transform =
        (scenario_d_backend_transform_t *) transform_data;
    uint64_t duration_us = 0;

    (void) ssl;
    (void) connection_data;

    if (srv == NULL || backend_transform == NULL ||
        backend_transform->tee_transform_handle == 0) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    if (tee_tls_d_record_open(&srv->tee_client,
                              backend_transform->tee_transform_handle,
                              aad, aad_len,
                              ciphertext, ciphertext_len,
                              plaintext, plaintext_size,
                              plaintext_len,
                              &duration_us) != 0) {
        srv->counters.record_open_failure++;
        log_tee_client_error(srv, "tee_record_open_failed");
        return MBEDTLS_ERR_SSL_INVALID_MAC;
    }

    srv->counters.record_open_success++;
    return 0;
}

static int setup_scenario_d_backend(server_ctx_t *srv)
{
    tee_tls_d_caps_t caps;
    uint64_t duration_us = 0;
    int ret;

    memset(&srv->tee_client, 0, sizeof(srv->tee_client));
    memset(&srv->crypto_backend, 0, sizeof(srv->crypto_backend));

    if (!srv->cfg.crypto_backend_enabled) {
        return 0;
    }

    if (tee_tls_d_open(&srv->tee_client) != 0) {
        srv->counters.tee_init_failure++;
        return -1;
    }
    srv->tee_client_initialized = true;
    srv->counters.tee_init_success++;

    if (tee_tls_d_get_caps(&srv->tee_client, &caps) != 0) {
        log_tee_client_error(srv, "tee_get_caps_failed");
        return -1;
    }

    if (caps.api_version != TEE_TLS_D_API_VERSION ||
        (caps.capabilities & TEE_TLS_D_CAP_CONNECTION_LIFECYCLE) == 0 ||
        (caps.capabilities & TEE_TLS_D_CAP_TRANSFORM_LIFECYCLE) == 0 ||
        (caps.capabilities & TEE_TLS_D_CAP_RECORD_AEAD) == 0 ||
        (caps.capabilities & TEE_TLS_D_CAP_KEY_SCHEDULE) == 0 ||
        (caps.capabilities & TEE_TLS_D_CAP_FINISHED) == 0 ||
        (caps.capabilities & TEE_TLS_D_CAP_ECDHE) == 0 ||
        (caps.capabilities & TEE_TLS_D_CAP_RESUMPTION) == 0 ||
        caps.max_connections == 0) {
        fprintf(stderr,
                "Scenario D TA capability mismatch: api=%" PRIu32
                " caps=0x%08" PRIx32 " max=%" PRIu32 "\n",
                caps.api_version,
                caps.capabilities,
                caps.max_connections);
        return -1;
    }

    if (srv->cfg.max_connections > (int) caps.max_connections) {
        fprintf(stderr,
                "Scenario D TA supports at most %" PRIu32
                " simultaneous backend connections; configured=%d\n",
                caps.max_connections,
                srv->cfg.max_connections);
        return -1;
    }

    if (srv->cfg.tee_selftest_enabled) {
        if (tee_tls_d_selftest(&srv->tee_client, &duration_us) != 0) {
            srv->counters.tee_selftest_failure++;
            log_tee_client_error(srv, "tee_selftest_failed");
            return -1;
        }
        srv->counters.tee_selftest_success++;
        log_line(srv, true, "DEBUG",
                 "d4_tee_selftest_ok tee_call_us=%" PRIu64,
                 duration_us);

        if (tee_tls_d_reset_stats(&srv->tee_client) != 0) {
            log_tee_client_error(srv, "tee_reset_stats_failed");
            return -1;
        }
    }

    srv->crypto_backend.api_version =
        MBEDTLS_SSL_TLS1_3_CRYPTO_BACKEND_API_VERSION;
    srv->crypto_backend.struct_size = sizeof(srv->crypto_backend);
    srv->crypto_backend.capabilities =
        MBEDTLS_SSL_TLS1_3_CRYPTO_BACKEND_CAP_CONNECTION_LIFECYCLE |
        MBEDTLS_SSL_TLS1_3_CRYPTO_BACKEND_CAP_TRANSFORM_LIFECYCLE |
        MBEDTLS_SSL_TLS1_3_CRYPTO_BACKEND_CAP_RECORD_AEAD |
        MBEDTLS_SSL_TLS1_3_CRYPTO_BACKEND_CAP_KEY_SCHEDULE |
        MBEDTLS_SSL_TLS1_3_CRYPTO_BACKEND_CAP_FINISHED |
        MBEDTLS_SSL_TLS1_3_CRYPTO_BACKEND_CAP_ECDHE |
        MBEDTLS_SSL_TLS1_3_CRYPTO_BACKEND_CAP_RESUMPTION;
    srv->crypto_backend.connection_init =
        scenario_d_backend_connection_init;
    srv->crypto_backend.connection_free =
        scenario_d_backend_connection_free;
    srv->crypto_backend.transform_free =
        scenario_d_backend_transform_free;
    srv->crypto_backend.transform_import =
        scenario_d_backend_transform_import;
    srv->crypto_backend.record_seal =
        scenario_d_backend_record_seal;
    srv->crypto_backend.record_open =
        scenario_d_backend_record_open;
    srv->crypto_backend.handshake_keys =
        scenario_d_backend_handshake_keys;
    srv->crypto_backend.application_keys =
        scenario_d_backend_application_keys;
    srv->crypto_backend.finished =
        scenario_d_backend_finished;
    srv->crypto_backend.server_key_share =
        scenario_d_backend_server_key_share;
    srv->crypto_backend.resumption_master =
        scenario_d_backend_resumption_master;
    srv->crypto_backend.resumption_psk =
        scenario_d_backend_resumption_psk;

    ret = mbedtls_ssl_conf_tls13_crypto_backend(&srv->ssl_conf,
                                                &srv->crypto_backend,
                                                srv);
    if (ret != 0) {
        char errbuf[256];
        format_mbedtls_error(ret, errbuf, sizeof(errbuf));
        fprintf(stderr,
                "ssl_conf_tls13_crypto_backend failed: %s\n",
                errbuf);
        return -1;
    }

    return 0;
}


static int setup_server_tls(server_ctx_t *srv)
{
    int ret;
    char errbuf[256];

    mbedtls_entropy_init(&srv->entropy);
    mbedtls_ctr_drbg_init(&srv->ctr_drbg);
    mbedtls_x509_crt_init(&srv->cert);
    mbedtls_pk_init(&srv->pkey);
    mbedtls_ssl_config_init(&srv->ssl_conf);
    mbedtls_ssl_cache_init(&srv->ssl_cache);
    mbedtls_ssl_ticket_init(&srv->ticket_ctx);
    srv->ticket_ctx_initialized = false;

    ret = psa_crypto_init();
    if (ret != PSA_SUCCESS) {
        fprintf(stderr, "psa_crypto_init failed: %d\n", ret);
        return -1;
    }

    ret = mbedtls_ctr_drbg_seed(&srv->ctr_drbg,
                                mbedtls_entropy_func,
                                &srv->entropy,
                                (const unsigned char *)RNG_PERS_STRING,
                                strlen(RNG_PERS_STRING));
    if (ret != 0) {
        format_mbedtls_error(ret, errbuf, sizeof(errbuf));
        fprintf(stderr, "ctr_drbg_seed failed: %s\n", errbuf);
        return -1;
    }

    ret = mbedtls_x509_crt_parse_file(&srv->cert, srv->cfg.cert_path);
    if (ret != 0) {
        format_mbedtls_error(ret, errbuf, sizeof(errbuf));
        fprintf(stderr, "x509_crt_parse_file failed: %s\n", errbuf);
        return -1;
    }

    ret = mbedtls_pk_parse_keyfile(&srv->pkey,
                                   srv->cfg.key_path,
                                   NULL,
                                   mbedtls_ctr_drbg_random,
                                   &srv->ctr_drbg);
    if (ret != 0) {
        format_mbedtls_error(ret, errbuf, sizeof(errbuf));
        fprintf(stderr, "pk_parse_keyfile failed: %s\n", errbuf);
        return -1;
    }

    if (validate_certificate_profile(srv) != 0) {
        return -1;
    }

    if (srv->cfg.external_signing_enabled) {
        if (setup_tee_signer_from_key(srv) != 0) {
            return -1;
        }

        /*
         * Literal Scenario C behavior: the key file is a prototype
         * provisioning source. Runtime CertificateVerify signatures use the
         * Scenario C TA and the parsed REE private-key context is released.
         */
        mbedtls_pk_free(&srv->pkey);
        mbedtls_pk_init(&srv->pkey);
        srv->provisioning_key_released = true;
    }

    if (srv->cfg.session_tickets_enabled &&
        srv->cfg.tee_ticket_protection_enabled) {
        srv->ticket_plain_cap = srv->cfg.ticket_plain_cap;
        srv->ticket_plain_buf = calloc(1, srv->ticket_plain_cap);
        if (!srv->ticket_plain_buf) {
            fprintf(stderr, "allocation failed for ticket_plain_buf\n");
            return -1;
        }

        if (setup_tee_km(srv) != 0) {
            return -1;
        }
    }

    ret = mbedtls_ssl_config_defaults(&srv->ssl_conf,
                                      MBEDTLS_SSL_IS_SERVER,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        format_mbedtls_error(ret, errbuf, sizeof(errbuf));
        fprintf(stderr, "ssl_config_defaults failed: %s\n", errbuf);
        return -1;
    }

    mbedtls_ssl_conf_authmode(&srv->ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&srv->ssl_conf,
                         mbedtls_ctr_drbg_random,
                         &srv->ctr_drbg);
    mbedtls_ssl_conf_dbg(&srv->ssl_conf, mbedtls_debug_cb, srv);
    mbedtls_debug_set_threshold(
        srv->cfg.log_mode == LOG_MODE_DEBUG ? srv->cfg.debug_level : 0);

    mbedtls_ssl_conf_min_tls_version(&srv->ssl_conf,
                                     MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&srv->ssl_conf,
                                     MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_ciphersuites(&srv->ssl_conf, g_tls13_ciphersuites);
    mbedtls_ssl_conf_groups(&srv->ssl_conf, g_tls13_groups);
    mbedtls_ssl_conf_sig_algs(&srv->ssl_conf, g_tls13_sig_algs);
    mbedtls_ssl_conf_tls13_key_exchange_modes(
        &srv->ssl_conf,
        MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ALL);

    if (srv->cfg.external_signing_enabled) {
        mbedtls_ssl_conf_async_private_cb(&srv->ssl_conf,
                                          async_sign_start_cb,
                                          NULL,
                                          async_resume_cb,
                                          async_cancel_cb,
                                          srv);
    }

    if (setup_scenario_d_backend(srv) != 0) {
        return -1;
    }

    ret = mbedtls_ssl_conf_own_cert(
        &srv->ssl_conf,
        &srv->cert,
        srv->cfg.external_signing_enabled ? &srv->cert.pk : &srv->pkey);
    if (ret != 0) {
        format_mbedtls_error(ret, errbuf, sizeof(errbuf));
        fprintf(stderr, "ssl_conf_own_cert failed: %s\n", errbuf);
        return -1;
    }

    if (srv->cfg.session_cache_enabled) {
        mbedtls_ssl_cache_set_max_entries(&srv->ssl_cache,
                                          srv->cfg.cache_max_entries);
        mbedtls_ssl_cache_set_timeout(&srv->ssl_cache,
                                      srv->cfg.cache_timeout_sec);
        mbedtls_ssl_conf_session_cache(&srv->ssl_conf,
                                       &srv->ssl_cache,
                                       mbedtls_ssl_cache_get,
                                       mbedtls_ssl_cache_set);
    }

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    if (srv->cfg.session_tickets_enabled) {
        if (!srv->cfg.tee_ticket_protection_enabled) {
            ret = mbedtls_ssl_ticket_setup(&srv->ticket_ctx,
                                           mbedtls_ctr_drbg_random,
                                           &srv->ctr_drbg,
                                           MBEDTLS_CIPHER_AES_256_GCM,
                                           srv->cfg.ticket_lifetime_sec);
            if (ret != 0) {
                format_mbedtls_error(ret, errbuf, sizeof(errbuf));
                fprintf(stderr, "ssl_ticket_setup failed: %s\n", errbuf);
                return -1;
            }
            srv->ticket_ctx_initialized = true;
        }

        mbedtls_ssl_conf_session_tickets_cb(&srv->ssl_conf,
                                            ticket_write_cb,
                                            ticket_parse_cb,
                                            srv);
        mbedtls_ssl_conf_new_session_tickets(&srv->ssl_conf, 1);
    } else {
        mbedtls_ssl_conf_new_session_tickets(&srv->ssl_conf, 0);
    }
#else
    if (srv->cfg.session_tickets_enabled) {
        fprintf(stderr,
                "session tickets requested, but "
                "MBEDTLS_SSL_SESSION_TICKETS is not enabled\n");
        return -1;
    }
#endif

    return 0;
}

static void free_server_tls(server_ctx_t *srv)
{
    if (srv->ticket_ctx_initialized) {
        mbedtls_ssl_ticket_free(&srv->ticket_ctx);
        srv->ticket_ctx_initialized = false;
    }

    free_tee_km(srv);
    free_tee_signer(srv);

    if (srv->tee_client_initialized) {
        tee_tls_d_close(&srv->tee_client);
        srv->tee_client_initialized = false;
    }

    mbedtls_ssl_cache_free(&srv->ssl_cache);
    mbedtls_ssl_config_free(&srv->ssl_conf);
    mbedtls_pk_free(&srv->pkey);
    mbedtls_x509_crt_free(&srv->cert);
    mbedtls_ctr_drbg_free(&srv->ctr_drbg);
    mbedtls_entropy_free(&srv->entropy);
}

static int add_epoll_fd(int epfd, int fd, uint32_t events, void *ptr) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.ptr = ptr;
    return epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
}

static int mod_epoll_fd(int epfd, int fd, uint32_t events, void *ptr) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.ptr = ptr;
    return epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
}

static void reset_client_slot(client_ctx_t *c, uint8_t *buf, size_t buf_len, int slot_index) {
    memset(c, 0, sizeof(*c));
    c->fd = -1;
    c->net.fd = -1;
    c->slot_index = slot_index;
    c->out_buf = buf;
    c->out_cap = buf_len;
}

static void update_client_interest(server_ctx_t *srv, int epfd, client_ctx_t *c) {
    uint32_t events = EPOLLRDHUP | EPOLLERR | EPOLLHUP;

    if (c->want_read) {
        events |= EPOLLIN;
    }
    if (c->want_write || (c->out_len > c->out_off)) {
        events |= EPOLLOUT;
    }

    if ((events & (EPOLLIN | EPOLLOUT)) == 0) {
        events |= EPOLLIN;
        c->want_read = true;
    }

    if (mod_epoll_fd(epfd, c->fd, events, c) != 0) {
        log_line(srv, true, "ERROR", "epoll_ctl MOD failed peer=%s errno=%d", c->peer_str, errno);
    }
}

static void close_client(server_ctx_t *srv, int epfd, client_ctx_t *c, close_reason_t reason) {
    if (!c->in_use) {
        return;
    }

    if (c->fd >= 0) {
        (void) epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
    }

    switch (reason) {
        case CLOSE_REASON_PEER_CLOSED: srv->counters.peer_closed++; break;
        case CLOSE_REASON_PEER_HANGUP: srv->counters.peer_hangup++; break;
        case CLOSE_REASON_HANDSHAKE_FAILURE: srv->counters.handshake_failure++; break;
        case CLOSE_REASON_HANDSHAKE_TIMEOUT: srv->counters.handshake_timeout++; break;
        case CLOSE_REASON_IDLE_TIMEOUT: srv->counters.idle_timeout++; break;
        case CLOSE_REASON_SSL_READ_FAILURE: srv->counters.ssl_read_failure++; break;
        case CLOSE_REASON_SSL_WRITE_FAILURE: srv->counters.ssl_write_failure++; break;
        case CLOSE_REASON_PAYLOAD_LIMIT: srv->counters.payload_limit_exceeded++; break;
        default: break;
    }

    log_line(srv, true,
             "DEBUG",
             "close slot=%d peer=%s reason=%s hs_ok=%d bytes_rx=%" PRIu64 " bytes_tx=%" PRIu64,
             c->slot_index,
             c->peer_str,
             close_reason_str(reason),
             c->handshake_ok ? 1 : 0,
             c->bytes_rx,
             c->bytes_tx);

    mbedtls_ssl_free(&c->ssl);

    /* Single socket owner: Mbed TLS net context closes the descriptor. */
    if (c->net.fd >= 0) {
        mbedtls_net_free(&c->net);
    }

    if (srv->counters.active_connections > 0) {
        srv->counters.active_connections--;
    }

    uint8_t *buf = c->out_buf;
    size_t cap = c->out_cap;
    int slot = c->slot_index;
    reset_client_slot(c, buf, cap, slot);
}

static int ssl_flush_pending(server_ctx_t *srv, int epfd, client_ctx_t *c) {
    while (c->out_off < c->out_len) {
        int ret = mbedtls_ssl_write(&c->ssl,
                                    c->out_buf + c->out_off,
                                    c->out_len - c->out_off);
        if (ret > 0) {
            c->out_off += (size_t) ret;
            c->bytes_tx += (uint64_t) ret;
            srv->counters.bytes_tx += (uint64_t) ret;
            ts_now(&c->last_activity_ts);
            continue;
        }

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            account_want(srv, c, ret);
            update_client_interest(srv, epfd, c);
            return 0;
        }

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            close_client(srv, epfd, c, CLOSE_REASON_PEER_CLOSED);
            return -1;
        }

        if (srv->cfg.log_mode == LOG_MODE_DEBUG) {
            char errbuf[256];
            format_mbedtls_error(ret, errbuf, sizeof(errbuf));
            log_line(srv, true, "ERROR", "ssl_write peer=%s failed=%s", c->peer_str, errbuf);
        }
        close_client(srv, epfd, c, CLOSE_REASON_SSL_WRITE_FAILURE);
        return -1;
    }

    if (c->out_len > 0) {
        srv->counters.echo_responses_completed++;
    }

    c->out_len = 0;
    c->out_off = 0;
    c->want_read = true;
    c->want_write = false;
    update_client_interest(srv, epfd, c);
    return 0;
}

static int ssl_do_handshake(server_ctx_t *srv, int epfd, client_ctx_t *c) {
    for (;;) {
        int ret = mbedtls_ssl_handshake(&c->ssl);
        if (ret == 0) {
            struct timespec now;
            ts_now(&now);
            c->handshake_done = true;
            c->handshake_ok = true;
            c->handshake_duration_us = ts_diff_us(&c->handshake_start_ts, &now);
            c->want_read = true;
            c->want_write = false;

            srv->counters.handshake_success++;
            srv->counters.handshake_duration_sum_us += c->handshake_duration_us;
            if (c->handshake_duration_us > srv->counters.handshake_duration_max_us) {
                srv->counters.handshake_duration_max_us = c->handshake_duration_us;
            }

            log_line(srv, true,
                     "DEBUG",
                     "handshake_ok slot=%d peer=%s version=%s ciphersuite=%s duration_us=%" PRIu64,
                     c->slot_index,
                     c->peer_str,
                     mbedtls_ssl_get_version(&c->ssl),
                     mbedtls_ssl_get_ciphersuite(&c->ssl),
                     c->handshake_duration_us);

            update_client_interest(srv, epfd, c);
            return 0;
        }

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            account_want(srv, c, ret);
            update_client_interest(srv, epfd, c);
            return 0;
        }

        if (srv->cfg.log_mode == LOG_MODE_DEBUG) {
            char errbuf[256];
            format_mbedtls_error(ret, errbuf, sizeof(errbuf));
            log_line(srv, true, "ERROR",
                     "handshake_failed peer=%s ret=%d hex=-0x%04x err=%s",
                     c->peer_str, ret, (unsigned int)(-ret), errbuf);
        }
        close_client(srv, epfd, c, CLOSE_REASON_HANDSHAKE_FAILURE);
        return -1;
    }
}

static int compact_pending_output(client_ctx_t *c) {
    if (c->out_off > 0 && c->out_off < c->out_len) {
        memmove(c->out_buf, c->out_buf + c->out_off, c->out_len - c->out_off);
        c->out_len -= c->out_off;
        c->out_off = 0;
    } else if (c->out_off >= c->out_len) {
        c->out_len = 0;
        c->out_off = 0;
    }
    return 0;
}

static int ssl_read_and_queue_echo(server_ctx_t *srv, int epfd, client_ctx_t *c) {
    unsigned char io_buf[16 * 1024];

    for (;;) {
        int ret = mbedtls_ssl_read(&c->ssl, io_buf, sizeof(io_buf));
        if (ret > 0) {
            size_t chunk = (size_t) ret;
            compact_pending_output(c);

            if (c->out_len + chunk > c->out_cap) {
                close_client(srv, epfd, c, CLOSE_REASON_PAYLOAD_LIMIT);
                return -1;
            }

            memcpy(c->out_buf + c->out_len, io_buf, chunk);
            c->out_len += chunk;
            c->bytes_rx += (uint64_t) chunk;
            srv->counters.bytes_rx += (uint64_t) chunk;
            srv->counters.echo_read_events++;
            c->echoed_once = true;
            ts_now(&c->last_activity_ts);

            if (ssl_flush_pending(srv, epfd, c) != 0) {
                return -1;
            }
            continue;
        }

        if (ret == 0 || ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            if (c->out_len > c->out_off) {
                if (ssl_flush_pending(srv, epfd, c) != 0) {
                    return -1;
                }
            }
            close_client(srv, epfd, c, CLOSE_REASON_PEER_CLOSED);
            return -1;
        }

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            account_want(srv, c, ret);
            update_client_interest(srv, epfd, c);
            return 0;
        }

        if (srv->cfg.log_mode == LOG_MODE_DEBUG) {
            char errbuf[256];
            format_mbedtls_error(ret, errbuf, sizeof(errbuf));
            log_line(srv, true, "ERROR", "ssl_read peer=%s failed=%s", c->peer_str, errbuf);
        }
        close_client(srv, epfd, c, CLOSE_REASON_SSL_READ_FAILURE);
        return -1;
    }
}

static void maybe_timeout_client(server_ctx_t *srv, int epfd, client_ctx_t *c) {
    if (!c->in_use) {
        return;
    }

    struct timespec now;
    ts_now(&now);
    uint64_t idle_ms = ts_diff_us(&c->last_activity_ts, &now) / 1000U;
    uint64_t hs_ms = ts_diff_us(&c->handshake_start_ts, &now) / 1000U;

    if (!c->handshake_done && hs_ms > (uint64_t) srv->cfg.handshake_timeout_ms) {
        close_client(srv, epfd, c, CLOSE_REASON_HANDSHAKE_TIMEOUT);
        return;
    }

    if (idle_ms > (uint64_t) srv->cfg.idle_timeout_ms) {
        close_client(srv, epfd, c, CLOSE_REASON_IDLE_TIMEOUT);
    }
}

static int accept_new_clients(server_ctx_t *srv, int epfd, int listen_fd,
                              client_ctx_t *clients, int client_cap) {
    for (;;) {
        struct sockaddr_storage ss;
        socklen_t ss_len = sizeof(ss);
        int fd = accept(listen_fd, (struct sockaddr *) &ss, &ss_len);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            log_line(srv, true, "ERROR", "accept failed errno=%d", errno);
            return -1;
        }

        if (set_nonblock(fd) != 0) {
            close(fd);
            log_line(srv, true, "ERROR", "set_nonblock accepted fd failed errno=%d", errno);
            continue;
        }

        int tcp_nodelay = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                       &tcp_nodelay, sizeof(tcp_nodelay)) != 0) {
            int saved_errno = errno;
            close(fd);
            log_line(srv, false, "ERROR",
                     "setsockopt TCP_NODELAY accepted fd failed errno=%d",
                     saved_errno);
            continue;
        }

        int slot = -1;
        for (int i = 0; i < client_cap; ++i) {
            if (!clients[i].in_use) {
                slot = i;
                break;
            }
        }

        if (slot < 0) {
            close(fd);
            srv->counters.dropped_no_slot++;
            continue;
        }

        client_ctx_t *c = &clients[slot];
        uint8_t *buf = c->out_buf;
        size_t cap = c->out_cap;
        reset_client_slot(c, buf, cap, slot);

        c->in_use = true;
        c->fd = fd;
        c->net.fd = fd;
        c->peer_addr = ss;
        c->peer_addr_len = ss_len;
        sockaddr_to_str(&ss, ss_len, c->peer_str, sizeof(c->peer_str));

        ts_now(&c->accepted_ts);
        ts_now(&c->last_activity_ts);
        ts_now(&c->handshake_start_ts);

        mbedtls_ssl_init(&c->ssl);
        int ret = mbedtls_ssl_setup(&c->ssl, &srv->ssl_conf);
        if (ret != 0) {
            if (srv->cfg.log_mode == LOG_MODE_DEBUG) {
                char errbuf[256];
                format_mbedtls_error(ret, errbuf, sizeof(errbuf));
                log_line(srv, true, "ERROR", "ssl_setup failed peer=%s err=%s", c->peer_str, errbuf);
            }
            mbedtls_ssl_free(&c->ssl);
            close(fd);
            reset_client_slot(c, buf, cap, slot);
            continue;
        }

        mbedtls_ssl_set_user_data_p(&c->ssl, srv);
        mbedtls_ssl_set_bio(&c->ssl, &c->net,
                            mbedtls_net_send, mbedtls_net_recv, NULL);
        c->want_read = true;
        c->want_write = false;

        if (add_epoll_fd(epfd, fd, EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP, c) != 0) {
            log_line(srv, true, "ERROR", "epoll_ctl ADD failed peer=%s errno=%d", c->peer_str, errno);
            mbedtls_ssl_free(&c->ssl);
            close(fd);
            reset_client_slot(c, buf, cap, slot);
            continue;
        }

        srv->counters.accepted_total++;
        srv->counters.active_connections++;

        log_line(srv, true, "DEBUG", "accept slot=%d peer=%s active=%" PRIu64,
                 slot, c->peer_str, srv->counters.active_connections);
    }
}


static void log_startup_manifest(server_ctx_t *srv)
{
    log_line(
        srv,
        false,
        "INFO",
        "manifest scenario=E platform=common-d4-case-a-v1 "
        "stage=CASE_A_LITERAL_B_C_D build=%s "
        "mbedtls_lineage=L1 mbedtls_l1_patch_version=%d "
        "tls=TLS1.3 cipher=TLS_AES_128_GCM_SHA256 "
        "sig=ecdsa_secp256r1_sha256 group=secp256r1 "
        "tls13_kex_modes=ephemeral+psk_ephemeral mutual_auth=no "
        "composition=B_ticket_wrap+C_certificate_verify+D4_crypto_backend "
        "ticket_protection=%s ticket_state_plaintext_location=ree "
        "external_signing_registered=%s certificate_verify_backend=%s "
        "ree_parsed_key_context_after_import=%s "
        "crypto_backend_registered=%s crypto_backend_api_version=%u "
        "tee_lifecycle_api_version=%u "
        "ecdhe_backend=%s key_schedule_backend=%s finished_backend=%s "
        "record_backend=%s resumption_backend=%s "
        "keyupdate_backend=unsupported zero_rtt=disabled "
        "tee_km_uuid=%s tee_sign_uuid=%s tee_d_uuid=%s",
        SCENARIO_E_BUILD_ID,
        MBEDTLS_SSL_L1_PATCH_VERSION,
        srv->cfg.tee_ticket_protection_enabled ?
            "tee_aes_gcm_literal_scenario_b" : "software",
        srv->cfg.external_signing_enabled ? "on" : "off",
        srv->cfg.external_signing_enabled ? "tee" : "software",
        srv->provisioning_key_released ? "released" : "present",
        srv->cfg.crypto_backend_enabled ? "on" : "off",
        MBEDTLS_SSL_TLS1_3_CRYPTO_BACKEND_API_VERSION,
        TEE_TLS_D_API_VERSION,
        srv->cfg.crypto_backend_enabled ? "tee_ephemeral_p256" : "software",
        srv->cfg.crypto_backend_enabled ?
            "tee_from_tee_ecdh_secret" : "software",
        srv->cfg.crypto_backend_enabled ? "tee" : "software",
        srv->cfg.crypto_backend_enabled ? "tee_aes_gcm" : "software",
        srv->cfg.crypto_backend_enabled ?
            "tee_resumption_master_and_psk" : "software",
        TA_KEY_MGMT_UUID_STR,
        TA_PRIVKEY_SIGN_UUID_STR,
        TA_TLS_D_BACKEND_UUID_STR);

    log_line(
        srv,
        false,
        "INFO",
        "manifest bind=%s:%s cert=%s key=%s max_conn=%d "
        "max_payload=%zu backlog=%d log_mode=%s debug_level=%d "
        "session_cache=%s session_tickets=%s "
        "strict_cert_profile=%s tee_ticket_protection=%s "
        "external_signing=%s crypto_backend=%s tee_selftest=%s "
        "async_debug_events=%s ticket_debug_hashes=%s "
        "ticket_plain_cap=%zu cache_timeout_sec=%d "
        "cache_max_entries=%d handshake_timeout_ms=%d "
        "idle_timeout_ms=%d summary_interval_ms=%d",
        srv->cfg.bind_ip,
        srv->cfg.port,
        srv->cfg.cert_path,
        srv->cfg.key_path,
        srv->cfg.max_connections,
        srv->cfg.max_payload,
        srv->cfg.listen_backlog,
        srv->cfg.log_mode == LOG_MODE_DEBUG ? "debug" : "measurement",
        srv->cfg.debug_level,
        srv->cfg.session_cache_enabled ? "on" : "off",
        srv->cfg.session_tickets_enabled ? "on" : "off",
        srv->cfg.strict_cert_profile ? "on" : "off",
        srv->cfg.tee_ticket_protection_enabled ? "on" : "off",
        srv->cfg.external_signing_enabled ? "on" : "off",
        srv->cfg.crypto_backend_enabled ? "on" : "off",
        srv->cfg.tee_selftest_enabled ? "on" : "off",
        srv->cfg.async_debug_events ? "on" : "off",
        srv->cfg.ticket_debug_hashes ? "on" : "off",
        srv->cfg.ticket_plain_cap,
        srv->cfg.cache_timeout_sec,
        srv->cfg.cache_max_entries,
        srv->cfg.handshake_timeout_ms,
        srv->cfg.idle_timeout_ms,
        srv->cfg.summary_interval_ms);
}

static void log_summary(server_ctx_t *srv, bool final) {
    struct timespec now;
    ts_now(&now);
    uint64_t uptime_ms = ts_diff_us(&srv->start_ts, &now) / 1000U;
    uint64_t hs_avg_us = 0;
    if (srv->counters.handshake_success > 0) {
        hs_avg_us = srv->counters.handshake_duration_sum_us / srv->counters.handshake_success;
    }

    log_line(srv, false, final ? "FINAL" : "SUMRY",
             "uptime_ms=%" PRIu64 " accepted=%" PRIu64 " active=%" PRIu64 " dropped_no_slot=%" PRIu64 " "
             "hs_ok=%" PRIu64 " hs_fail=%" PRIu64 " hs_timeout=%" PRIu64 " hs_avg_us=%" PRIu64 " hs_max_us=%" PRIu64 " "
             "ticket_parse_ok=%" PRIu64 " ticket_parse_fail=%" PRIu64 " ticket_write_ok=%" PRIu64 " ticket_write_fail=%" PRIu64 " "
             "tee_init_ok=%" PRIu64 " tee_init_fail=%" PRIu64 " tee_selftest_ok=%" PRIu64 " tee_selftest_fail=%" PRIu64 " "
             "backend_conn_init_ok=%" PRIu64 " backend_conn_init_fail=%" PRIu64 " backend_conn_free=%" PRIu64 " "
             "tee_conn_open_ok=%" PRIu64 " tee_conn_open_fail=%" PRIu64 " tee_conn_close_ok=%" PRIu64 " tee_conn_close_fail=%" PRIu64 " "
             "backend_transform_free=%" PRIu64 " "
             "backend_transform_import_ok=%" PRIu64 " backend_transform_import_fail=%" PRIu64 " "
             "tee_transform_import_ok=%" PRIu64 " tee_transform_import_fail=%" PRIu64 " "
             "tee_transform_free_ok=%" PRIu64 " tee_transform_free_fail=%" PRIu64 " "
             "record_seal_ok=%" PRIu64 " record_seal_fail=%" PRIu64 " "
             "record_open_ok=%" PRIu64 " record_open_fail=%" PRIu64 " "
             "backend_hs_keys_ok=%" PRIu64 " backend_hs_keys_fail=%" PRIu64 " "
             "tee_hs_keys_ok=%" PRIu64 " tee_hs_keys_fail=%" PRIu64 " "
             "backend_app_keys_ok=%" PRIu64 " backend_app_keys_fail=%" PRIu64 " "
             "tee_app_keys_ok=%" PRIu64 " tee_app_keys_fail=%" PRIu64 " "
             "finished_ok=%" PRIu64 " finished_fail=%" PRIu64 " "
             "tee_finished_ok=%" PRIu64 " tee_finished_fail=%" PRIu64 " "
             "backend_server_key_share_ok=%" PRIu64 " backend_server_key_share_fail=%" PRIu64 " "
             "tee_server_key_share_ok=%" PRIu64 " tee_server_key_share_fail=%" PRIu64 " "
             "backend_resumption_master_ok=%" PRIu64 " backend_resumption_master_fail=%" PRIu64 " "
             "tee_resumption_master_ok=%" PRIu64 " tee_resumption_master_fail=%" PRIu64 " "
             "backend_resumption_psk_ok=%" PRIu64 " backend_resumption_psk_fail=%" PRIu64 " "
             "tee_resumption_psk_ok=%" PRIu64 " tee_resumption_psk_fail=%" PRIu64 " "
             "km_init_ok=%" PRIu64 " km_init_fail=%" PRIu64 " "
             "km_selftest_ok=%" PRIu64 " km_selftest_fail=%" PRIu64 " "
             "km_wrap_ok=%" PRIu64 " km_wrap_fail=%" PRIu64 " "
             "km_unwrap_ok=%" PRIu64 " km_unwrap_fail=%" PRIu64 " "
             "km_call_sum_us=%" PRIu64 " km_call_max_us=%" PRIu64 " "
             "sign_init_ok=%" PRIu64 " sign_init_fail=%" PRIu64 " "
             "sign_import_ok=%" PRIu64 " sign_import_fail=%" PRIu64 " "
             "sign_selftest_ok=%" PRIu64 " sign_selftest_fail=%" PRIu64 " "
             "sign_ok=%" PRIu64 " sign_fail=%" PRIu64 " "
             "sign_call_sum_us=%" PRIu64 " sign_call_max_us=%" PRIu64 " "
             "async_start=%" PRIu64 " async_resume=%" PRIu64 " async_cancel=%" PRIu64 " "
             "echo_reads=%" PRIu64 " echo_responses=%" PRIu64 " bytes_rx=%" PRIu64 " bytes_tx=%" PRIu64 " "
             "payload_limit=%" PRIu64 " idle_timeout=%" PRIu64 " peer_closed=%" PRIu64 " peer_hangup=%" PRIu64 " "
             "ssl_read_fail=%" PRIu64 " ssl_write_fail=%" PRIu64 " epoll_calls=%" PRIu64 " epoll_events=%" PRIu64 " "
             "want_read=%" PRIu64 " want_write=%" PRIu64,
             uptime_ms,
             srv->counters.accepted_total,
             srv->counters.active_connections,
             srv->counters.dropped_no_slot,
             srv->counters.handshake_success,
             srv->counters.handshake_failure,
             srv->counters.handshake_timeout,
             hs_avg_us,
             srv->counters.handshake_duration_max_us,
             srv->counters.ticket_parse_success,
             srv->counters.ticket_parse_failure,
             srv->counters.ticket_write_success,
             srv->counters.ticket_write_failure,
             srv->counters.tee_init_success,
             srv->counters.tee_init_failure,
             srv->counters.tee_selftest_success,
             srv->counters.tee_selftest_failure,
             srv->counters.backend_connection_init_success,
             srv->counters.backend_connection_init_failure,
             srv->counters.backend_connection_free_calls,
             srv->counters.tee_connection_open_success,
             srv->counters.tee_connection_open_failure,
             srv->counters.tee_connection_close_success,
             srv->counters.tee_connection_close_failure,
             srv->counters.backend_transform_free_calls,
             srv->counters.backend_transform_import_success,
             srv->counters.backend_transform_import_failure,
             srv->counters.tee_transform_import_success,
             srv->counters.tee_transform_import_failure,
             srv->counters.tee_transform_free_success,
             srv->counters.tee_transform_free_failure,
             srv->counters.record_seal_success,
             srv->counters.record_seal_failure,
             srv->counters.record_open_success,
             srv->counters.record_open_failure,
             srv->counters.backend_handshake_keys_success,
             srv->counters.backend_handshake_keys_failure,
             srv->counters.tee_handshake_keys_success,
             srv->counters.tee_handshake_keys_failure,
             srv->counters.backend_application_keys_success,
             srv->counters.backend_application_keys_failure,
             srv->counters.tee_application_keys_success,
             srv->counters.tee_application_keys_failure,
             srv->counters.finished_success,
             srv->counters.finished_failure,
             srv->counters.tee_finished_success,
             srv->counters.tee_finished_failure,
             srv->counters.backend_server_key_share_success,
             srv->counters.backend_server_key_share_failure,
             srv->counters.tee_server_key_share_success,
             srv->counters.tee_server_key_share_failure,
             srv->counters.backend_resumption_master_success,
             srv->counters.backend_resumption_master_failure,
             srv->counters.tee_resumption_master_success,
             srv->counters.tee_resumption_master_failure,
             srv->counters.backend_resumption_psk_success,
             srv->counters.backend_resumption_psk_failure,
             srv->counters.tee_resumption_psk_success,
             srv->counters.tee_resumption_psk_failure,
             srv->counters.km_init_success,
             srv->counters.km_init_failure,
             srv->counters.km_selftest_success,
             srv->counters.km_selftest_failure,
             srv->counters.km_wrap_success,
             srv->counters.km_wrap_failure,
             srv->counters.km_unwrap_success,
             srv->counters.km_unwrap_failure,
             srv->counters.km_call_duration_sum_us,
             srv->counters.km_call_duration_max_us,
             srv->counters.sign_init_success,
             srv->counters.sign_init_failure,
             srv->counters.sign_import_success,
             srv->counters.sign_import_failure,
             srv->counters.sign_selftest_success,
             srv->counters.sign_selftest_failure,
             srv->counters.sign_success,
             srv->counters.sign_failure,
             srv->counters.sign_call_duration_sum_us,
             srv->counters.sign_call_duration_max_us,
             srv->counters.async_sign_start_calls,
             srv->counters.async_resume_calls,
             srv->counters.async_cancel_calls,
             srv->counters.echo_read_events,
             srv->counters.echo_responses_completed,
             srv->counters.bytes_rx,
             srv->counters.bytes_tx,
             srv->counters.payload_limit_exceeded,
             srv->counters.idle_timeout,
             srv->counters.peer_closed,
             srv->counters.peer_hangup,
             srv->counters.ssl_read_failure,
             srv->counters.ssl_write_failure,
             srv->counters.epoll_wait_calls,
             srv->counters.epoll_events,
             srv->counters.want_read_returns,
             srv->counters.want_write_returns);

    srv->last_summary_ts = now;
}

static void maybe_log_periodic_summary(server_ctx_t *srv) {
    struct timespec now;
    ts_now(&now);
    uint64_t elapsed_ms = ts_diff_us(&srv->last_summary_ts, &now) / 1000U;
    if (elapsed_ms >= (uint64_t) srv->cfg.summary_interval_ms) {
        log_summary(srv, false);
    }
}

int main(int argc, char **argv) {
    server_ctx_t srv;
    memset(&srv, 0, sizeof(srv));
    default_config(&srv.cfg);

    int parse_ret = parse_args(argc, argv, &srv.cfg);
    if (parse_ret == 1) {
        return 0;
    }
    if (parse_ret != 0) {
        usage(argv[0]);
        return 1;
    }

    srv.log_fp = fopen(srv.cfg.log_path, "a");
    if (!srv.log_fp) {
        fprintf(stderr, "failed to open log file: %s\n", srv.cfg.log_path);
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) != 0 ||
        sigaction(SIGTERM, &sa, NULL) != 0) {
        perror("sigaction");
        fclose(srv.log_fp);
        return 1;
    }

    /*
     * A peer that disconnects while TLS output is pending must become a
     * connection-level write error, not terminate the entire server process.
     */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGPIPE, &sa, NULL) != 0) {
        perror("sigaction(SIGPIPE)");
        fclose(srv.log_fp);
        return 1;
    }

    ts_now(&srv.start_ts);
    srv.last_summary_ts = srv.start_ts;

    if (setup_server_tls(&srv) != 0) {
        free_server_tls(&srv);
        fclose(srv.log_fp);
        return 1;
    }

    if (srv.cfg.max_payload > 0 &&
        (size_t) srv.cfg.max_connections > SIZE_MAX / srv.cfg.max_payload) {
        fprintf(stderr, "buffer pool size overflow\n");
        free_server_tls(&srv);
        fclose(srv.log_fp);
        return 1;
    }

    size_t pool_size = (size_t) srv.cfg.max_connections * srv.cfg.max_payload;
    uint8_t *buffer_pool = calloc(1, pool_size);
    client_ctx_t *clients = calloc((size_t) srv.cfg.max_connections, sizeof(client_ctx_t));
    struct epoll_event *events = calloc((size_t) srv.cfg.max_events, sizeof(struct epoll_event));
    if (!buffer_pool || !clients || !events) {
        fprintf(stderr, "allocation failed for buffer pool, clients, or events\n");
        free(events);
        free(clients);
        free(buffer_pool);
        free_server_tls(&srv);
        fclose(srv.log_fp);
        return 1;
    }

    for (int i = 0; i < srv.cfg.max_connections; ++i) {
        reset_client_slot(&clients[i], buffer_pool + ((size_t) i * srv.cfg.max_payload), srv.cfg.max_payload, i);
    }

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        free(events);
        free(clients);
        free(buffer_pool);
        free_server_tls(&srv);
        fclose(srv.log_fp);
        return 1;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (set_nonblock(listen_fd) != 0) {
        perror("set_nonblock(listen_fd)");
        close(listen_fd);
        free(events);
        free(clients);
        free(buffer_pool);
        free_server_tls(&srv);
        fclose(srv.log_fp);
        return 1;
    }

    struct sockaddr_in addr4;
    memset(&addr4, 0, sizeof(addr4));
    addr4.sin_family = AF_INET;
    addr4.sin_port = htons((uint16_t) atoi(srv.cfg.port));
    if (inet_pton(AF_INET, srv.cfg.bind_ip, &addr4.sin_addr) != 1) {
        fprintf(stderr, "invalid bind IPv4 address: %s\n", srv.cfg.bind_ip);
        close(listen_fd);
        free(events);
        free(clients);
        free(buffer_pool);
        free_server_tls(&srv);
        fclose(srv.log_fp);
        return 1;
    }

    if (bind(listen_fd, (struct sockaddr *) &addr4, sizeof(addr4)) != 0) {
        perror("bind");
        close(listen_fd);
        free(events);
        free(clients);
        free(buffer_pool);
        free_server_tls(&srv);
        fclose(srv.log_fp);
        return 1;
    }

    if (listen(listen_fd, srv.cfg.listen_backlog) != 0) {
        perror("listen");
        close(listen_fd);
        free(events);
        free(clients);
        free(buffer_pool);
        free_server_tls(&srv);
        fclose(srv.log_fp);
        return 1;
    }

    int epfd = epoll_create1(0);
    if (epfd < 0) {
        perror("epoll_create1");
        close(listen_fd);
        free(events);
        free(clients);
        free(buffer_pool);
        free_server_tls(&srv);
        fclose(srv.log_fp);
        return 1;
    }

    void *listen_marker = (void *) (uintptr_t) 1;
    if (add_epoll_fd(epfd, listen_fd, EPOLLIN | EPOLLERR | EPOLLHUP, listen_marker) != 0) {
        perror("epoll_ctl(listen)");
        close(epfd);
        close(listen_fd);
        free(events);
        free(clients);
        free(buffer_pool);
        free_server_tls(&srv);
        fclose(srv.log_fp);
        return 1;
    }

    log_startup_manifest(&srv);

    while (!g_stop) {
        int n = epoll_wait(epfd, events, srv.cfg.max_events, 100);
        srv.counters.epoll_wait_calls++;
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            log_line(&srv, false, "ERROR", "epoll_wait failed errno=%d", errno);
            break;
        }

        srv.counters.epoll_events += (uint64_t) n;

        for (int i = 0; i < n; ++i) {
            if (events[i].data.ptr == listen_marker) {
                accept_new_clients(&srv, epfd, listen_fd, clients, srv.cfg.max_connections);
                continue;
            }

            client_ctx_t *c = (client_ctx_t *) events[i].data.ptr;
            if (!c || !c->in_use) {
                continue;
            }

            uint32_t revents = events[i].events;

            /* EPOLLERR is immediately fatal. EPOLLRDHUP/EPOLLHUP may arrive
             * together with EPOLLIN while the final TLS record is still queued.
             * Process pending TLS input/output before acting on peer shutdown. */
            if ((revents & EPOLLERR) != 0) {
                close_client(&srv, epfd, c, CLOSE_REASON_PEER_HANGUP);
                continue;
            }

            if (!c->handshake_done) {
                if (ssl_do_handshake(&srv, epfd, c) != 0) {
                    continue;
                }
            }
            if (!c->in_use) {
                continue;
            }

            if (c->handshake_done && (revents & EPOLLOUT) != 0 && c->out_len > c->out_off) {
                srv.counters.echo_write_events++;
                if (ssl_flush_pending(&srv, epfd, c) != 0) {
                    continue;
                }
            }
            if (!c->in_use) {
                continue;
            }

            if (c->handshake_done && (revents & EPOLLIN) != 0) {
                if (ssl_read_and_queue_echo(&srv, epfd, c) != 0) {
                    continue;
                }
            }
            if (!c->in_use) {
                continue;
            }

            if ((revents & (EPOLLRDHUP | EPOLLHUP)) != 0) {
                close_client(&srv, epfd, c, CLOSE_REASON_PEER_HANGUP);
                continue;
            }
        }

        for (int i = 0; i < srv.cfg.max_connections; ++i) {
            if (clients[i].in_use) {
                maybe_timeout_client(&srv, epfd, &clients[i]);
            }
        }

        maybe_log_periodic_summary(&srv);
    }

    for (int i = 0; i < srv.cfg.max_connections; ++i) {
        if (clients[i].in_use) {
            close_client(&srv, epfd, &clients[i], CLOSE_REASON_SERVER_SHUTDOWN);
        }
    }

    log_summary(&srv, true);

    close(epfd);
    close(listen_fd);
    free(events);
    free(clients);
    free(buffer_pool);
    free_server_tls(&srv);
    fclose(srv.log_fp);
    return 0;
}
