#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef CLIENT_GIT_COMMIT
#define CLIENT_GIT_COMMIT "unknown"
#endif

#define CLIENT_VERSION "0.1.1"

#if OPENSSL_VERSION_NUMBER < 0x30500000L
#error "This reference client requires OpenSSL 3.5 or newer."
#endif

#define U64_NA UINT64_MAX
#define MAX_STR 512
#define MAX_ERROR 1024
#define MAX_PATTERN 256
#define MAX_LINE 2048
#define NS_PER_S 1000000000ULL
#define NS_PER_MS 1000000ULL
#define NS_PER_US 1000ULL

/*
 * Native TLS reference measurement client for the TEE/TLS robustness study.
 *
 * Author: Florian Förster <florian.foerster@tha.de>
 *
 * Target TLS library: OpenSSL 3.5 LTS or newer 3.x/4.x with the APIs used here.
 */

typedef enum {
    WORKLOAD_FULL_HANDSHAKE = 0,
    WORKLOAD_RESUMPTION,
    WORKLOAD_RECORD
} workload_t;

typedef enum {
    FAIL_NONE = 0,
    FAIL_CONFIG,
    FAIL_SOCKET_CREATE,
    FAIL_SOURCE_BIND,
    FAIL_INTERFACE_BIND,
    FAIL_TCP_CONNECT,
    FAIL_TLS_OBJECT,
    FAIL_TLS_HANDSHAKE,
    FAIL_TLS_PROFILE,
    FAIL_SEND,
    FAIL_RECEIVE,
    FAIL_PAYLOAD_VERIFY,
    FAIL_SHUTDOWN,
    FAIL_SESSION_TICKET,
    FAIL_RESUMPTION
} failure_stage_t;

typedef struct {
    char ca_file[MAX_STR];
    char server_name[MAX_STR];
    bool verify_peer;
    bool verify_hostname;
    bool strict_shutdown;
    char ciphersuite[MAX_STR];
    char group[MAX_STR];
    char signature_algorithm[MAX_STR];

    uint64_t duration_s;
    uint64_t probe_interval_ms;

    uint64_t tcp_connect_timeout_ms;
    uint64_t tls_handshake_timeout_ms;
    uint64_t io_timeout_ms;

    size_t payload_size;
    char payload_mode[64];
    uint64_t payload_seed;
    unsigned char payload_pattern[MAX_PATTERN];
    size_t payload_pattern_len;

    bool tcp_nodelay;

    char resumption_session_policy[32];

    bool record_reconnect_on_failure;
    uint64_t record_reconnect_backoff_ms;

    char output_directory[MAX_STR];
    char csv_prefix[128];
    bool stdout_progress;
} config_t;

typedef struct {
    char config_path[PATH_MAX];
    char scenario[8];
    workload_t workload;
    char workload_name[32];
    unsigned repetition;
    char server[MAX_STR];
    char port[16];
    char source_address[MAX_STR];
    char interface_name[IFNAMSIZ];
    char output_dir_override[MAX_STR];
    char run_id[64];
    bool run_id_set;

    bool duration_override_set;
    uint64_t duration_override_s;
    bool interval_override_set;
    uint64_t interval_override_ms;
    bool payload_override_set;
    size_t payload_override_size;
} cli_t;

typedef struct {
    SSL_SESSION *latest;
    unsigned callback_count;
} session_store_t;

typedef struct {
    int fd;
    SSL *ssl;
    uint64_t connection_id;
    uint64_t request_on_connection;
    bool session_reused;
    char tls_version[32];
    char cipher[128];
    char group[128];
    char peer_signature[128];
} tls_conn_t;

typedef struct {
    uint64_t probe_id;
    uint64_t wall_time_utc_ns;
    uint64_t elapsed_run_us;
    uint64_t scheduled_elapsed_us;
    uint64_t schedule_lag_us;
    uint64_t missed_slots_before;
    uint64_t connection_id;
    uint64_t request_on_connection;
    bool reconnect;
    bool session_reused;
    bool session_reused_valid;

    uint64_t tcp_connect_us;
    uint64_t tls_handshake_us;
    uint64_t connection_establishment_us;
    uint64_t send_us;
    uint64_t ttfb_us;
    uint64_t recv_us;
    uint64_t app_rtt_us;
    uint64_t tls_shutdown_us;
    uint64_t probe_total_us;

    size_t bytes_sent;
    size_t bytes_received;
    bool payload_match;
    bool payload_match_valid;
    long first_mismatch_offset;

    int result_code;
    failure_stage_t failure_stage;
    char tls_version[32];
    char cipher[128];
    char group[128];
    char peer_signature[128];
    char error_message[MAX_ERROR];
    char openssl_error[MAX_ERROR];
} probe_row_t;

typedef struct {
    config_t cfg;
    cli_t cli;
    SSL_CTX *ssl_ctx;
    FILE *csv;
    char csv_path[PATH_MAX];
    char metadata_path[PATH_MAX];
    unsigned char *payload;
    uint64_t next_connection_id;
    session_store_t sessions;
    unsigned char *resumption_seed_der;
    size_t resumption_seed_der_len;
} app_t;

static void fatal_usage(const char *msg);

static uint64_t ts_to_ns(const struct timespec *ts) {
    return (uint64_t)ts->tv_sec * NS_PER_S + (uint64_t)ts->tv_nsec;
}

static uint64_t monotonic_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime(CLOCK_MONOTONIC)");
        exit(EXIT_FAILURE);
    }
    return ts_to_ns(&ts);
}

static uint64_t realtime_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        perror("clock_gettime(CLOCK_REALTIME)");
        exit(EXIT_FAILURE);
    }
    return ts_to_ns(&ts);
}

static uint64_t elapsed_us(uint64_t start_ns, uint64_t end_ns) {
    if (end_ns < start_ns) {
        return 0;
    }
    return (end_ns - start_ns) / NS_PER_US;
}

static void ns_to_timespec(uint64_t ns, struct timespec *ts) {
    ts->tv_sec = (time_t)(ns / NS_PER_S);
    ts->tv_nsec = (long)(ns % NS_PER_S);
}

static void sleep_until_ns(uint64_t deadline_ns) {
    struct timespec ts;
    ns_to_timespec(deadline_ns, &ts);
    for (;;) {
        int rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL);
        if (rc == 0) {
            return;
        }
        if (rc != EINTR) {
            errno = rc;
            perror("clock_nanosleep");
            return;
        }
    }
}

static void sleep_ms(uint64_t ms) {
    struct timespec req = {
        .tv_sec = (time_t)(ms / 1000ULL),
        .tv_nsec = (long)((ms % 1000ULL) * NS_PER_MS),
    };
    while (nanosleep(&req, &req) != 0 && errno == EINTR) {
    }
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') {
        ++s;
    }
    char *end = s + strlen(s);
    while (end > s) {
        char c = end[-1];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
            break;
        }
        --end;
    }
    *end = '\0';
    return s;
}

static bool parse_bool(const char *s, bool *out) {
    if (strcasecmp(s, "true") == 0 || strcmp(s, "1") == 0 || strcasecmp(s, "yes") == 0) {
        *out = true;
        return true;
    }
    if (strcasecmp(s, "false") == 0 || strcmp(s, "0") == 0 || strcasecmp(s, "no") == 0) {
        *out = false;
        return true;
    }
    return false;
}

static bool parse_u64(const char *s, uint64_t *out) {
    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno != 0 || end == s || *trim(end) != '\0') {
        return false;
    }
    *out = (uint64_t)v;
    return true;
}

static bool parse_size(const char *s, size_t *out) {
    uint64_t v = 0;
    if (!parse_u64(s, &v) || v == 0 || v > SIZE_MAX) {
        return false;
    }
    *out = (size_t)v;
    return true;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool parse_hex_pattern(const char *s, unsigned char *out, size_t *out_len) {
    size_t len = strlen(s);
    if (len == 0 || (len % 2) != 0 || len / 2 > MAX_PATTERN) {
        return false;
    }
    size_t n = len / 2;
    for (size_t i = 0; i < n; ++i) {
        int hi = hex_value(s[2 * i]);
        int lo = hex_value(s[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    *out_len = n;
    return true;
}

static void config_defaults(config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->server_name, sizeof(cfg->server_name), "%s", "tls-echo-server");
    cfg->verify_peer = true;
    cfg->verify_hostname = false;
    cfg->strict_shutdown = false;
    snprintf(cfg->ciphersuite, sizeof(cfg->ciphersuite), "%s", "TLS_AES_128_GCM_SHA256");
    snprintf(cfg->group, sizeof(cfg->group), "%s", "P-256");
    snprintf(cfg->signature_algorithm, sizeof(cfg->signature_algorithm), "%s", "ecdsa_secp256r1_sha256");
    cfg->duration_s = 300;
    cfg->probe_interval_ms = 1000;
    cfg->tcp_connect_timeout_ms = 5000;
    cfg->tls_handshake_timeout_ms = 5000;
    cfg->io_timeout_ms = 5000;
    cfg->payload_size = 1024;
    snprintf(cfg->payload_mode, sizeof(cfg->payload_mode), "%s", "fixed_pattern");
    cfg->payload_seed = 12345;
    cfg->payload_pattern[0] = 0xa5;
    cfg->payload_pattern_len = 1;
    cfg->tcp_nodelay = true;
    snprintf(cfg->resumption_session_policy, sizeof(cfg->resumption_session_policy), "%s", "reuse_seed");
    cfg->record_reconnect_on_failure = true;
    cfg->record_reconnect_backoff_ms = 1000;
    snprintf(cfg->output_directory, sizeof(cfg->output_directory), "%s", "./results");
    snprintf(cfg->csv_prefix, sizeof(cfg->csv_prefix), "%s", "tls_reference");
    cfg->stdout_progress = true;
}

static int set_config_value(config_t *cfg, const char *key, const char *value, char *err, size_t errlen) {
    uint64_t u64 = 0;
    bool b = false;
    size_t sz = 0;

#define COPY_FIELD(field) do { \
    if (strlen(value) >= sizeof(cfg->field)) { \
        snprintf(err, errlen, "value too long for %s", key); \
        return -1; \
    } \
    snprintf(cfg->field, sizeof(cfg->field), "%s", value); \
    return 0; \
} while (0)

    if (strcmp(key, "tls.ca_file") == 0) COPY_FIELD(ca_file);
    if (strcmp(key, "tls.server_name") == 0) COPY_FIELD(server_name);
    if (strcmp(key, "tls.ciphersuite") == 0) COPY_FIELD(ciphersuite);
    if (strcmp(key, "tls.group") == 0) COPY_FIELD(group);
    if (strcmp(key, "tls.signature_algorithm") == 0) COPY_FIELD(signature_algorithm);
    if (strcmp(key, "payload.mode") == 0) COPY_FIELD(payload_mode);
    if (strcmp(key, "output.directory") == 0) COPY_FIELD(output_directory);
    if (strcmp(key, "output.csv_prefix") == 0) COPY_FIELD(csv_prefix);
    if (strcmp(key, "resumption.session_policy") == 0) COPY_FIELD(resumption_session_policy);

    if (strcmp(key, "tls.verify_peer") == 0 || strcmp(key, "tls.verify_hostname") == 0 ||
        strcmp(key, "tls.strict_shutdown") == 0 || strcmp(key, "socket.tcp_nodelay") == 0 ||
        strcmp(key, "record.reconnect_on_failure") == 0 || strcmp(key, "output.stdout_progress") == 0) {
        if (!parse_bool(value, &b)) {
            snprintf(err, errlen, "invalid boolean for %s: %s", key, value);
            return -1;
        }
        if (strcmp(key, "tls.verify_peer") == 0) cfg->verify_peer = b;
        else if (strcmp(key, "tls.verify_hostname") == 0) cfg->verify_hostname = b;
        else if (strcmp(key, "tls.strict_shutdown") == 0) cfg->strict_shutdown = b;
        else if (strcmp(key, "socket.tcp_nodelay") == 0) cfg->tcp_nodelay = b;
        else if (strcmp(key, "record.reconnect_on_failure") == 0) cfg->record_reconnect_on_failure = b;
        else cfg->stdout_progress = b;
        return 0;
    }

    if (strcmp(key, "run.duration_s") == 0 || strcmp(key, "run.probe_interval_ms") == 0 ||
        strcmp(key, "timeouts.tcp_connect_ms") == 0 || strcmp(key, "timeouts.tls_handshake_ms") == 0 ||
        strcmp(key, "timeouts.io_ms") == 0 || strcmp(key, "payload.seed") == 0 ||
        strcmp(key, "record.reconnect_backoff_ms") == 0) {
        if (!parse_u64(value, &u64)) {
            snprintf(err, errlen, "invalid integer for %s: %s", key, value);
            return -1;
        }
        if (strcmp(key, "run.duration_s") == 0) cfg->duration_s = u64;
        else if (strcmp(key, "run.probe_interval_ms") == 0) cfg->probe_interval_ms = u64;
        else if (strcmp(key, "timeouts.tcp_connect_ms") == 0) cfg->tcp_connect_timeout_ms = u64;
        else if (strcmp(key, "timeouts.tls_handshake_ms") == 0) cfg->tls_handshake_timeout_ms = u64;
        else if (strcmp(key, "timeouts.io_ms") == 0) cfg->io_timeout_ms = u64;
        else if (strcmp(key, "payload.seed") == 0) cfg->payload_seed = u64;
        else cfg->record_reconnect_backoff_ms = u64;
        return 0;
    }

    if (strcmp(key, "payload.size_bytes") == 0) {
        if (!parse_size(value, &sz)) {
            snprintf(err, errlen, "invalid payload.size_bytes: %s", value);
            return -1;
        }
        cfg->payload_size = sz;
        return 0;
    }

    if (strcmp(key, "payload.pattern_hex") == 0) {
        if (!parse_hex_pattern(value, cfg->payload_pattern, &cfg->payload_pattern_len)) {
            snprintf(err, errlen, "invalid payload.pattern_hex");
            return -1;
        }
        return 0;
    }

    snprintf(err, errlen, "unknown configuration key: %s", key);
    return -1;
#undef COPY_FIELD
}

static int load_config_file(const char *path, config_t *cfg, char *err, size_t errlen) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        /* Bound externally supplied path/error text so diagnostics cannot trigger
         * -Wformat-truncation under -Werror on compilers that track PATH_MAX. */
        snprintf(err, errlen, "cannot open config %.700s: %.250s", path, strerror(errno));
        return -1;
    }

    char line[MAX_LINE];
    unsigned line_no = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        ++line_no;
        char *p = trim(line);
        if (*p == '\0' || *p == '#') {
            continue;
        }
        char *eq = strchr(p, '=');
        if (!eq) {
            snprintf(err, errlen, "%.900s:%u: expected key=value", path, line_no);
            fclose(fp);
            return -1;
        }
        *eq = '\0';
        char *key = trim(p);
        char *value = trim(eq + 1);
        char *comment = strchr(value, '#');
        if (comment) {
            *comment = '\0';
            value = trim(value);
        }
        if (*key == '\0') {
            snprintf(err, errlen, "%.900s:%u: empty key", path, line_no);
            fclose(fp);
            return -1;
        }
        if (set_config_value(cfg, key, value, err, errlen) != 0) {
            char tmp[MAX_ERROR];
            snprintf(tmp, sizeof(tmp), "line %u: %.900s", line_no, err);
            snprintf(err, errlen, "%s", tmp);
            fclose(fp);
            return -1;
        }
    }
    if (ferror(fp)) {
        snprintf(err, errlen, "error reading config %.900s", path);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

static int validate_config(const config_t *cfg, char *err, size_t errlen) {
    if (cfg->verify_peer && cfg->ca_file[0] == '\0') {
        snprintf(err, errlen, "tls.ca_file is required when tls.verify_peer=true");
        return -1;
    }
    if (cfg->verify_hostname && cfg->server_name[0] == '\0') {
        snprintf(err, errlen, "tls.server_name is required when tls.verify_hostname=true");
        return -1;
    }
    if (cfg->duration_s == 0 || cfg->probe_interval_ms == 0) {
        snprintf(err, errlen, "run.duration_s and run.probe_interval_ms must be > 0");
        return -1;
    }
    if (cfg->tcp_connect_timeout_ms == 0 || cfg->tls_handshake_timeout_ms == 0 || cfg->io_timeout_ms == 0) {
        snprintf(err, errlen, "all timeout values must be > 0");
        return -1;
    }
    if (cfg->payload_size == 0) {
        snprintf(err, errlen, "payload.size_bytes must be > 0");
        return -1;
    }
    if (strcasecmp(cfg->payload_mode, "fixed_pattern") != 0 &&
        strcasecmp(cfg->payload_mode, "deterministic_random") != 0) {
        snprintf(err, errlen, "payload.mode must be fixed_pattern or deterministic_random");
        return -1;
    }
    if (strcasecmp(cfg->payload_mode, "fixed_pattern") == 0 && cfg->payload_pattern_len == 0) {
        snprintf(err, errlen, "payload.pattern_hex must not be empty for fixed_pattern");
        return -1;
    }
    if (strcmp(cfg->resumption_session_policy, "reuse_seed") != 0 &&
        strcmp(cfg->resumption_session_policy, "chain") != 0) {
        snprintf(err, errlen, "resumption.session_policy must be reuse_seed or chain");
        return -1;
    }
    return 0;
}

static const char *workload_name(workload_t w) {
    switch (w) {
        case WORKLOAD_FULL_HANDSHAKE: return "full-handshake";
        case WORKLOAD_RESUMPTION: return "resumption";
        case WORKLOAD_RECORD: return "record";
    }
    return "unknown";
}

static bool parse_workload(const char *s, workload_t *out) {
    if (strcmp(s, "full-handshake") == 0 || strcmp(s, "full_handshake") == 0) {
        *out = WORKLOAD_FULL_HANDSHAKE;
        return true;
    }
    if (strcmp(s, "resumption") == 0) {
        *out = WORKLOAD_RESUMPTION;
        return true;
    }
    if (strcmp(s, "record") == 0) {
        *out = WORKLOAD_RECORD;
        return true;
    }
    return false;
}

static void print_usage(FILE *fp, const char *prog) {
    fprintf(fp,
        "Usage: %s --config FILE --scenario A|B|C|D|E --workload MODE --repetition N --server HOST --port PORT [options]\n"
        "\n"
        "Required run identity / placement:\n"
        "  --config FILE                 Strict key=value configuration file\n"
        "  --scenario A|B|C|D|E         Scenario identifier; metadata only\n"
        "  --workload MODE              full-handshake | resumption | record\n"
        "  --repetition N               Repetition number (>=1)\n"
        "  --server HOST                DUT address/hostname\n"
        "  --port PORT                  DUT TCP port\n"
        "\n"
        "Optional placement / automation:\n"
        "  --source-address ADDR        Bind local source address before connect\n"
        "  --interface IFACE            Linux SO_BINDTODEVICE (may require privileges)\n"
        "  --output-dir DIR             Override output.directory\n"
        "  --run-id ID                  Orchestrator-provided run identifier\n"
        "\n"
        "Pilot overrides:\n"
        "  --duration-s N               Override run.duration_s\n"
        "  --probe-interval-ms N        Override run.probe_interval_ms\n"
        "  --payload-size N             Override payload.size_bytes\n"
        "\n"
        "Other:\n"
        "  --help                       Show this help\n",
        prog);
}

static void fatal_usage(const char *msg) {
    if (msg) fprintf(stderr, "Error: %s\n", msg);
    fprintf(stderr, "Use --help for usage.\n");
    exit(2);
}

static int parse_cli(int argc, char **argv, cli_t *cli) {
    memset(cli, 0, sizeof(*cli));

    enum {
        OPT_SCENARIO = 1000,
        OPT_WORKLOAD,
        OPT_REPETITION,
        OPT_SERVER,
        OPT_PORT,
        OPT_SOURCE_ADDRESS,
        OPT_INTERFACE,
        OPT_OUTPUT_DIR,
        OPT_RUN_ID,
        OPT_DURATION_S,
        OPT_INTERVAL_MS,
        OPT_PAYLOAD_SIZE,
    };

    static const struct option opts[] = {
        {"config", required_argument, NULL, 'c'},
        {"scenario", required_argument, NULL, OPT_SCENARIO},
        {"workload", required_argument, NULL, OPT_WORKLOAD},
        {"repetition", required_argument, NULL, OPT_REPETITION},
        {"server", required_argument, NULL, OPT_SERVER},
        {"port", required_argument, NULL, OPT_PORT},
        {"source-address", required_argument, NULL, OPT_SOURCE_ADDRESS},
        {"interface", required_argument, NULL, OPT_INTERFACE},
        {"output-dir", required_argument, NULL, OPT_OUTPUT_DIR},
        {"run-id", required_argument, NULL, OPT_RUN_ID},
        {"duration-s", required_argument, NULL, OPT_DURATION_S},
        {"probe-interval-ms", required_argument, NULL, OPT_INTERVAL_MS},
        {"payload-size", required_argument, NULL, OPT_PAYLOAD_SIZE},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    bool have_config = false, have_scenario = false, have_workload = false;
    bool have_repetition = false, have_server = false, have_port = false;

    for (;;) {
        int idx = 0;
        int c = getopt_long(argc, argv, "c:h", opts, &idx);
        if (c == -1) break;
        uint64_t u64 = 0;
        size_t sz = 0;
        switch (c) {
            case 'c':
                snprintf(cli->config_path, sizeof(cli->config_path), "%s", optarg);
                have_config = true;
                break;
            case 'h':
                print_usage(stdout, argv[0]);
                exit(0);
            case OPT_SCENARIO:
                if (strlen(optarg) != 1 || strchr("ABCDE", optarg[0]) == NULL) fatal_usage("--scenario must be A, B, C, D, or E");
                cli->scenario[0] = optarg[0];
                cli->scenario[1] = '\0';
                have_scenario = true;
                break;
            case OPT_WORKLOAD:
                if (!parse_workload(optarg, &cli->workload)) fatal_usage("invalid --workload");
                snprintf(cli->workload_name, sizeof(cli->workload_name), "%s", workload_name(cli->workload));
                have_workload = true;
                break;
            case OPT_REPETITION:
                if (!parse_u64(optarg, &u64) || u64 == 0 || u64 > UINT_MAX) fatal_usage("invalid --repetition");
                cli->repetition = (unsigned)u64;
                have_repetition = true;
                break;
            case OPT_SERVER:
                snprintf(cli->server, sizeof(cli->server), "%s", optarg);
                have_server = true;
                break;
            case OPT_PORT:
                if (!parse_u64(optarg, &u64) || u64 == 0 || u64 > 65535) fatal_usage("invalid --port");
                snprintf(cli->port, sizeof(cli->port), "%llu", (unsigned long long)u64);
                have_port = true;
                break;
            case OPT_SOURCE_ADDRESS:
                snprintf(cli->source_address, sizeof(cli->source_address), "%s", optarg);
                break;
            case OPT_INTERFACE:
                if (strlen(optarg) >= sizeof(cli->interface_name)) fatal_usage("--interface is too long");
                snprintf(cli->interface_name, sizeof(cli->interface_name), "%s", optarg);
                break;
            case OPT_OUTPUT_DIR:
                snprintf(cli->output_dir_override, sizeof(cli->output_dir_override), "%s", optarg);
                break;
            case OPT_RUN_ID:
                if (strlen(optarg) >= sizeof(cli->run_id)) fatal_usage("--run-id is too long");
                snprintf(cli->run_id, sizeof(cli->run_id), "%s", optarg);
                cli->run_id_set = true;
                break;
            case OPT_DURATION_S:
                if (!parse_u64(optarg, &u64) || u64 == 0) fatal_usage("invalid --duration-s");
                cli->duration_override_s = u64;
                cli->duration_override_set = true;
                break;
            case OPT_INTERVAL_MS:
                if (!parse_u64(optarg, &u64) || u64 == 0) fatal_usage("invalid --probe-interval-ms");
                cli->interval_override_ms = u64;
                cli->interval_override_set = true;
                break;
            case OPT_PAYLOAD_SIZE:
                if (!parse_size(optarg, &sz)) fatal_usage("invalid --payload-size");
                cli->payload_override_size = sz;
                cli->payload_override_set = true;
                break;
            default:
                return -1;
        }
    }

    if (optind != argc) fatal_usage("unexpected positional arguments");
    if (!have_config || !have_scenario || !have_workload || !have_repetition || !have_server || !have_port) {
        fatal_usage("missing required option(s)");
    }
    return 0;
}

static void apply_cli_overrides(app_t *app) {
    if (app->cli.duration_override_set) app->cfg.duration_s = app->cli.duration_override_s;
    if (app->cli.interval_override_set) app->cfg.probe_interval_ms = app->cli.interval_override_ms;
    if (app->cli.payload_override_set) app->cfg.payload_size = app->cli.payload_override_size;
    if (app->cli.output_dir_override[0]) {
        snprintf(app->cfg.output_directory, sizeof(app->cfg.output_directory), "%s", app->cli.output_dir_override);
    }
}

static int mkdir_p(const char *path) {
    char tmp[PATH_MAX];
    if (strlen(path) >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    if (len == 0) return 0;
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';

    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0775) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0775) != 0 && errno != EEXIST) return -1;
    return 0;
}

static void generate_run_id(char *out, size_t outlen) {
    unsigned char bytes[12];
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) {
        snprintf(out, outlen, "pid-%ld-%llu", (long)getpid(), (unsigned long long)monotonic_ns());
        return;
    }
    char *p = out;
    size_t remain = outlen;
    for (size_t i = 0; i < sizeof(bytes) && remain > 2; ++i) {
        int n = snprintf(p, remain, "%02x", bytes[i]);
        if (n != 2) break;
        p += 2;
        remain -= 2;
    }
}

static void openssl_error_string(char *out, size_t outlen) {
    out[0] = '\0';
    size_t used = 0;
    unsigned long e;
    while ((e = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(e, buf, sizeof(buf));
        size_t need = strlen(buf) + (used ? 3 : 0);
        if (used + need + 1 >= outlen) break;
        if (used) {
            memcpy(out + used, " | ", 3);
            used += 3;
        }
        size_t blen = strlen(buf);
        memcpy(out + used, buf, blen);
        used += blen;
        out[used] = '\0';
    }
}

static int set_socket_timeout_ms(int fd, uint64_t ms) {
    struct timeval tv;
    tv.tv_sec = (time_t)(ms / 1000ULL);
    tv.tv_usec = (suseconds_t)((ms % 1000ULL) * 1000ULL);
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) return -1;
    return 0;
}

static int bind_source_address(int fd, int family, const char *source, char *err, size_t errlen) {
    if (!source || !*source) return 0;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST;

    struct addrinfo *res = NULL;
    int gai = getaddrinfo(source, "0", &hints, &res);
    if (gai != 0) {
        snprintf(err, errlen, "source address %s invalid for address family: %s", source, gai_strerror(gai));
        return -1;
    }
    int rc = bind(fd, res->ai_addr, res->ai_addrlen);
    if (rc != 0) {
        snprintf(err, errlen, "bind source address %s failed: %s", source, strerror(errno));
    }
    freeaddrinfo(res);
    return rc;
}

static int connect_with_timeout(const app_t *app, probe_row_t *row, int *out_fd) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo *res = NULL;
    int gai = getaddrinfo(app->cli.server, app->cli.port, &hints, &res);
    if (gai != 0) {
        snprintf(row->error_message, sizeof(row->error_message), "getaddrinfo: %s", gai_strerror(gai));
        row->failure_stage = FAIL_TCP_CONNECT;
        return -1;
    }

    uint64_t start = monotonic_ns();
    int last_errno = 0;

    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            last_errno = errno;
            row->failure_stage = FAIL_SOCKET_CREATE;
            continue;
        }

        if (app->cfg.tcp_nodelay) {
            int one = 1;
            if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) != 0) {
                last_errno = errno;
                close(fd);
                continue;
            }
        }

#ifdef SO_BINDTODEVICE
        if (app->cli.interface_name[0] != '\0') {
            if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                           app->cli.interface_name, strlen(app->cli.interface_name) + 1) != 0) {
                snprintf(row->error_message, sizeof(row->error_message),
                         "SO_BINDTODEVICE(%s) failed: %s", app->cli.interface_name, strerror(errno));
                row->failure_stage = FAIL_INTERFACE_BIND;
                close(fd);
                freeaddrinfo(res);
                return -1;
            }
        }
#endif

        char bind_err[MAX_ERROR];
        if (bind_source_address(fd, ai->ai_family, app->cli.source_address, bind_err, sizeof(bind_err)) != 0) {
            snprintf(row->error_message, sizeof(row->error_message), "%s", bind_err);
            row->failure_stage = FAIL_SOURCE_BIND;
            close(fd);
            freeaddrinfo(res);
            return -1;
        }

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
            last_errno = errno;
            close(fd);
            continue;
        }

        int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc != 0 && errno != EINPROGRESS) {
            last_errno = errno;
            close(fd);
            continue;
        }

        if (rc != 0) {
            struct pollfd pfd = {.fd = fd, .events = POLLOUT};
            int timeout = app->cfg.tcp_connect_timeout_ms > INT_MAX ? INT_MAX : (int)app->cfg.tcp_connect_timeout_ms;
            rc = poll(&pfd, 1, timeout);
            if (rc <= 0) {
                last_errno = (rc == 0) ? ETIMEDOUT : errno;
                close(fd);
                continue;
            }
            int soerr = 0;
            socklen_t slen = sizeof(soerr);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) != 0 || soerr != 0) {
                last_errno = soerr ? soerr : errno;
                close(fd);
                continue;
            }
        }

        if (fcntl(fd, F_SETFL, flags) != 0) {
            last_errno = errno;
            close(fd);
            continue;
        }

        row->tcp_connect_us = elapsed_us(start, monotonic_ns());
        *out_fd = fd;
        freeaddrinfo(res);
        return 0;
    }

    row->tcp_connect_us = elapsed_us(start, monotonic_ns());
    row->failure_stage = FAIL_TCP_CONNECT;
    snprintf(row->error_message, sizeof(row->error_message), "TCP connect failed: %s", strerror(last_errno ? last_errno : ECONNREFUSED));
    freeaddrinfo(res);
    return -1;
}

static int new_session_cb(SSL *ssl, SSL_SESSION *sess) {
    session_store_t *store = (session_store_t *)SSL_get_app_data(ssl);
    if (!store || !SSL_SESSION_is_resumable(sess)) {
        return 0;
    }
    if (store->latest) {
        SSL_SESSION_free(store->latest);
        store->latest = NULL;
    }
    store->latest = sess;
    store->callback_count++;
    return 1; /* retain callback-provided application reference */
}

static SSL_SESSION *session_store_take(session_store_t *store) {
    SSL_SESSION *s = store->latest;
    store->latest = NULL;
    return s;
}

static void session_store_clear(session_store_t *store) {
    if (store->latest) {
        SSL_SESSION_free(store->latest);
        store->latest = NULL;
    }
}

static SSL_CTX *make_ssl_ctx(const config_t *cfg, char *err, size_t errlen) {
    ERR_clear_error();
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        openssl_error_string(err, errlen);
        return NULL;
    }

    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) ||
        !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)) {
        openssl_error_string(err, errlen);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (!SSL_CTX_set_ciphersuites(ctx, cfg->ciphersuite)) {
        openssl_error_string(err, errlen);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (!SSL_CTX_set1_groups_list(ctx, cfg->group)) {
        openssl_error_string(err, errlen);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (!SSL_CTX_set1_sigalgs_list(ctx, cfg->signature_algorithm)) {
        openssl_error_string(err, errlen);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (cfg->verify_peer) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (!SSL_CTX_load_verify_locations(ctx, cfg->ca_file, NULL)) {
            openssl_error_string(err, errlen);
            SSL_CTX_free(ctx);
            return NULL;
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
    SSL_CTX_sess_set_new_cb(ctx, new_session_cb);
    return ctx;
}

static void probe_row_init(probe_row_t *row) {
    memset(row, 0, sizeof(*row));
    row->tcp_connect_us = U64_NA;
    row->tls_handshake_us = U64_NA;
    row->connection_establishment_us = U64_NA;
    row->send_us = U64_NA;
    row->ttfb_us = U64_NA;
    row->recv_us = U64_NA;
    row->app_rtt_us = U64_NA;
    row->tls_shutdown_us = U64_NA;
    row->probe_total_us = U64_NA;
    row->first_mismatch_offset = -1;
    row->result_code = 0;
    row->failure_stage = FAIL_NONE;
}

static const char *failure_stage_name(failure_stage_t s) {
    switch (s) {
        case FAIL_NONE: return "";
        case FAIL_CONFIG: return "config";
        case FAIL_SOCKET_CREATE: return "socket_create";
        case FAIL_SOURCE_BIND: return "source_bind";
        case FAIL_INTERFACE_BIND: return "interface_bind";
        case FAIL_TCP_CONNECT: return "tcp_connect";
        case FAIL_TLS_OBJECT: return "tls_object";
        case FAIL_TLS_HANDSHAKE: return "tls_handshake";
        case FAIL_TLS_PROFILE: return "tls_profile";
        case FAIL_SEND: return "send";
        case FAIL_RECEIVE: return "receive";
        case FAIL_PAYLOAD_VERIFY: return "payload_verify";
        case FAIL_SHUTDOWN: return "shutdown";
        case FAIL_SESSION_TICKET: return "session_ticket";
        case FAIL_RESUMPTION: return "resumption";
    }
    return "unknown";
}

static void tls_conn_close(tls_conn_t *conn) {
    if (!conn) return;
    if (conn->ssl) {
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }
}

static int validate_negotiated_profile(const app_t *app, tls_conn_t *conn, probe_row_t *row,
                                       bool expect_resumed) {
    const char *version = SSL_get_version(conn->ssl);
    const SSL_CIPHER *cipher = SSL_get_current_cipher(conn->ssl);
    const char *cipher_name = cipher ? SSL_CIPHER_get_name(cipher) : "";
    const char *group_name = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    group_name = SSL_get0_group_name(conn->ssl);
#endif
    if (!group_name) {
        int nid = SSL_get_negotiated_group(conn->ssl);
        group_name = (nid != NID_undef) ? OBJ_nid2sn(nid) : "";
    }
    const char *sig_name = "";
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    const char *tmp_sig = NULL;
    if (SSL_get0_peer_signature_name(conn->ssl, &tmp_sig) == 1 && tmp_sig) {
        sig_name = tmp_sig;
    }
#endif

    snprintf(conn->tls_version, sizeof(conn->tls_version), "%s", version ? version : "");
    snprintf(conn->cipher, sizeof(conn->cipher), "%s", cipher_name ? cipher_name : "");
    snprintf(conn->group, sizeof(conn->group), "%s", group_name ? group_name : "");
    snprintf(conn->peer_signature, sizeof(conn->peer_signature), "%s", sig_name ? sig_name : "");
    conn->session_reused = SSL_session_reused(conn->ssl) == 1;

    snprintf(row->tls_version, sizeof(row->tls_version), "%s", conn->tls_version);
    snprintf(row->cipher, sizeof(row->cipher), "%s", conn->cipher);
    snprintf(row->group, sizeof(row->group), "%s", conn->group);
    snprintf(row->peer_signature, sizeof(row->peer_signature), "%s", conn->peer_signature);
    row->session_reused = conn->session_reused;
    row->session_reused_valid = true;

    if (strcmp(conn->tls_version, "TLSv1.3") != 0) {
        snprintf(row->error_message, sizeof(row->error_message), "unexpected TLS version: %s", conn->tls_version);
        row->failure_stage = FAIL_TLS_PROFILE;
        return -1;
    }
    if (strcmp(conn->cipher, app->cfg.ciphersuite) != 0) {
        snprintf(row->error_message, sizeof(row->error_message), "unexpected ciphersuite: %s", conn->cipher);
        row->failure_stage = FAIL_TLS_PROFILE;
        return -1;
    }
    int group_nid = SSL_get_negotiated_group(conn->ssl);
    if (group_nid != NID_X9_62_prime256v1) {
        snprintf(row->error_message, sizeof(row->error_message), "unexpected negotiated group: %s", conn->group);
        row->failure_stage = FAIL_TLS_PROFILE;
        return -1;
    }
    if (expect_resumed != conn->session_reused) {
        snprintf(row->error_message, sizeof(row->error_message), "session reuse invariant failed: expected=%s actual=%s",
                 expect_resumed ? "true" : "false", conn->session_reused ? "true" : "false");
        row->failure_stage = expect_resumed ? FAIL_RESUMPTION : FAIL_TLS_PROFILE;
        return -1;
    }
    if (!conn->session_reused && app->cfg.signature_algorithm[0] != '\0') {
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
        if (conn->peer_signature[0] == '\0' || strcmp(conn->peer_signature, app->cfg.signature_algorithm) != 0) {
            snprintf(row->error_message, sizeof(row->error_message), "unexpected peer signature scheme: %s", conn->peer_signature);
            row->failure_stage = FAIL_TLS_PROFILE;
            return -1;
        }
#endif
    }
    if (app->cfg.verify_peer && SSL_get_verify_result(conn->ssl) != X509_V_OK) {
        snprintf(row->error_message, sizeof(row->error_message), "certificate verification failed: %ld", SSL_get_verify_result(conn->ssl));
        row->failure_stage = FAIL_TLS_PROFILE;
        return -1;
    }
    return 0;
}

static int open_tls_connection(app_t *app, tls_conn_t *conn, probe_row_t *row,
                               SSL_SESSION *resume_session, bool expect_resumed,
                               session_store_t *capture_store) {
    memset(conn, 0, sizeof(*conn));
    conn->fd = -1;
    conn->connection_id = ++app->next_connection_id;

    uint64_t establish_start = monotonic_ns();
    if (connect_with_timeout(app, row, &conn->fd) != 0) {
        row->connection_establishment_us = elapsed_us(establish_start, monotonic_ns());
        return -1;
    }

    if (set_socket_timeout_ms(conn->fd, app->cfg.tls_handshake_timeout_ms) != 0) {
        snprintf(row->error_message, sizeof(row->error_message), "setting handshake socket timeout failed: %s", strerror(errno));
        row->failure_stage = FAIL_TLS_HANDSHAKE;
        row->connection_establishment_us = elapsed_us(establish_start, monotonic_ns());
        tls_conn_close(conn);
        return -1;
    }

    ERR_clear_error();
    conn->ssl = SSL_new(app->ssl_ctx);
    if (!conn->ssl) {
        row->failure_stage = FAIL_TLS_OBJECT;
        openssl_error_string(row->openssl_error, sizeof(row->openssl_error));
        row->connection_establishment_us = elapsed_us(establish_start, monotonic_ns());
        tls_conn_close(conn);
        return -1;
    }

    SSL_set_app_data(conn->ssl, capture_store);

    if (app->cfg.server_name[0] != '\0') {
        if (SSL_set_tlsext_host_name(conn->ssl, app->cfg.server_name) != 1) {
            row->failure_stage = FAIL_TLS_OBJECT;
            openssl_error_string(row->openssl_error, sizeof(row->openssl_error));
            tls_conn_close(conn);
            return -1;
        }
        if (app->cfg.verify_hostname && SSL_set1_host(conn->ssl, app->cfg.server_name) != 1) {
            row->failure_stage = FAIL_TLS_OBJECT;
            openssl_error_string(row->openssl_error, sizeof(row->openssl_error));
            tls_conn_close(conn);
            return -1;
        }
    }

    if (SSL_set_fd(conn->ssl, conn->fd) != 1) {
        row->failure_stage = FAIL_TLS_OBJECT;
        openssl_error_string(row->openssl_error, sizeof(row->openssl_error));
        tls_conn_close(conn);
        return -1;
    }

    if (resume_session) {
        if (SSL_set_session(conn->ssl, resume_session) != 1) {
            row->failure_stage = FAIL_RESUMPTION;
            openssl_error_string(row->openssl_error, sizeof(row->openssl_error));
            tls_conn_close(conn);
            return -1;
        }
    }

    uint64_t hs_start = monotonic_ns();
    ERR_clear_error();
    int rc = SSL_connect(conn->ssl);
    uint64_t hs_end = monotonic_ns();
    row->tls_handshake_us = elapsed_us(hs_start, hs_end);
    row->connection_establishment_us = elapsed_us(establish_start, hs_end);
    if (rc != 1) {
        row->failure_stage = FAIL_TLS_HANDSHAKE;
        openssl_error_string(row->openssl_error, sizeof(row->openssl_error));
        if (row->openssl_error[0] == '\0') {
            snprintf(row->error_message, sizeof(row->error_message), "SSL_connect failed (SSL_get_error=%d)", SSL_get_error(conn->ssl, rc));
        }
        tls_conn_close(conn);
        return -1;
    }

    if (set_socket_timeout_ms(conn->fd, app->cfg.io_timeout_ms) != 0) {
        snprintf(row->error_message, sizeof(row->error_message), "setting I/O socket timeout failed: %s", strerror(errno));
        row->failure_stage = FAIL_RECEIVE;
        tls_conn_close(conn);
        return -1;
    }

    if (validate_negotiated_profile(app, conn, row, expect_resumed) != 0) {
        tls_conn_close(conn);
        return -1;
    }

    row->connection_id = conn->connection_id;
    row->request_on_connection = 0;
    return 0;
}

static uint64_t xorshift64star(uint64_t *state) {
    uint64_t x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 2685821657736338717ULL;
}

static void build_payload(const config_t *cfg, unsigned char *buf, size_t len, uint64_t probe_id) {
    if (strcasecmp(cfg->payload_mode, "fixed_pattern") == 0) {
        for (size_t i = 0; i < len; ++i) {
            buf[i] = cfg->payload_pattern[i % cfg->payload_pattern_len];
        }
        return;
    }
    uint64_t state = cfg->payload_seed ^ (probe_id * 0x9e3779b97f4a7c15ULL) ^ 0xd1b54a32d192ed03ULL;
    if (state == 0) state = 1;
    uint64_t word = 0;
    unsigned remain = 0;
    for (size_t i = 0; i < len; ++i) {
        if (remain == 0) {
            word = xorshift64star(&state);
            remain = 8;
        }
        buf[i] = (unsigned char)(word & 0xffu);
        word >>= 8;
        --remain;
    }
}

static long first_mismatch(const unsigned char *a, const unsigned char *b, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (a[i] != b[i]) return (long)i;
    }
    return -1;
}

static int ssl_write_all(SSL *ssl, const unsigned char *buf, size_t len, size_t *written,
                         char *ossl, size_t ossllen) {
    *written = 0;
    while (*written < len) {
        size_t n = 0;
        ERR_clear_error();
        if (SSL_write_ex(ssl, buf + *written, len - *written, &n) != 1) {
            openssl_error_string(ossl, ossllen);
            return -1;
        }
        if (n == 0) return -1;
        *written += n;
    }
    return 0;
}

static int ssl_read_exact(SSL *ssl, unsigned char *buf, size_t len, size_t *received,
                          uint64_t *first_byte_ns, char *ossl, size_t ossllen) {
    *received = 0;
    *first_byte_ns = 0;
    while (*received < len) {
        size_t n = 0;
        ERR_clear_error();
        if (SSL_read_ex(ssl, buf + *received, len - *received, &n) != 1) {
            openssl_error_string(ossl, ossllen);
            return -1;
        }
        if (n == 0) return -1;
        if (*first_byte_ns == 0) *first_byte_ns = monotonic_ns();
        *received += n;
    }
    return 0;
}

static int perform_echo(app_t *app, tls_conn_t *conn, probe_row_t *row, uint64_t payload_id) {
    unsigned char *recv_buf = malloc(app->cfg.payload_size);
    if (!recv_buf) {
        row->failure_stage = FAIL_RECEIVE;
        snprintf(row->error_message, sizeof(row->error_message), "malloc receive buffer failed");
        return -1;
    }
    build_payload(&app->cfg, app->payload, app->cfg.payload_size, payload_id);

    uint64_t send_start = monotonic_ns();
    size_t written = 0;
    if (ssl_write_all(conn->ssl, app->payload, app->cfg.payload_size, &written,
                      row->openssl_error, sizeof(row->openssl_error)) != 0) {
        row->send_us = elapsed_us(send_start, monotonic_ns());
        row->bytes_sent = written;
        row->failure_stage = FAIL_SEND;
        free(recv_buf);
        return -1;
    }
    uint64_t send_end = monotonic_ns();
    row->send_us = elapsed_us(send_start, send_end);
    row->bytes_sent = written;

    uint64_t recv_start = monotonic_ns();
    size_t received = 0;
    uint64_t first_byte = 0;
    if (ssl_read_exact(conn->ssl, recv_buf, app->cfg.payload_size, &received, &first_byte,
                       row->openssl_error, sizeof(row->openssl_error)) != 0) {
        row->recv_us = elapsed_us(recv_start, monotonic_ns());
        row->app_rtt_us = elapsed_us(send_start, monotonic_ns());
        row->bytes_received = received;
        row->failure_stage = FAIL_RECEIVE;
        free(recv_buf);
        return -1;
    }
    uint64_t recv_end = monotonic_ns();
    row->ttfb_us = first_byte ? elapsed_us(send_end, first_byte) : 0;
    row->recv_us = elapsed_us(recv_start, recv_end);
    row->app_rtt_us = elapsed_us(send_start, recv_end);
    row->bytes_received = received;

    row->payload_match = (received == app->cfg.payload_size && memcmp(app->payload, recv_buf, app->cfg.payload_size) == 0);
    row->payload_match_valid = true;
    if (!row->payload_match) {
        row->first_mismatch_offset = first_mismatch(app->payload, recv_buf,
                                                    received < app->cfg.payload_size ? received : app->cfg.payload_size);
        if (row->first_mismatch_offset < 0 && received != app->cfg.payload_size) {
            row->first_mismatch_offset = (long)received;
        }
        row->failure_stage = FAIL_PAYLOAD_VERIFY;
        row->result_code = -1;
        free(recv_buf);
        return -1;
    }

    conn->request_on_connection++;
    row->request_on_connection = conn->request_on_connection;
    free(recv_buf);
    return 0;
}

static int tls_shutdown_measure(const config_t *cfg, tls_conn_t *conn, probe_row_t *row) {
    if (!conn || !conn->ssl) return 0;
    uint64_t start = monotonic_ns();
    ERR_clear_error();
    int rc = SSL_shutdown(conn->ssl);
    row->tls_shutdown_us = elapsed_us(start, monotonic_ns());
    if (rc < 0 && cfg->strict_shutdown) {
        row->failure_stage = FAIL_SHUTDOWN;
        openssl_error_string(row->openssl_error, sizeof(row->openssl_error));
        if (row->openssl_error[0] == '\0') {
            snprintf(row->error_message, sizeof(row->error_message), "SSL_shutdown failed");
        }
        return -1;
    }
    return 0;
}

static void copy_conn_metadata(probe_row_t *row, const tls_conn_t *conn) {
    row->connection_id = conn->connection_id;
    row->request_on_connection = conn->request_on_connection;
    row->session_reused = conn->session_reused;
    row->session_reused_valid = true;
    snprintf(row->tls_version, sizeof(row->tls_version), "%s", conn->tls_version);
    snprintf(row->cipher, sizeof(row->cipher), "%s", conn->cipher);
    snprintf(row->group, sizeof(row->group), "%s", conn->group);
    snprintf(row->peer_signature, sizeof(row->peer_signature), "%s", conn->peer_signature);
}

static int preflight_full(app_t *app) {
    probe_row_t row;
    probe_row_init(&row);
    tls_conn_t conn;
    if (open_tls_connection(app, &conn, &row, NULL, false, NULL) != 0) {
        fprintf(stderr, "Full-handshake preflight failed at %s: %s %s\n",
                failure_stage_name(row.failure_stage), row.error_message, row.openssl_error);
        return -1;
    }
    if (perform_echo(app, &conn, &row, UINT64_MAX - 1) != 0) {
        fprintf(stderr, "Full-handshake echo preflight failed at %s: %s %s\n",
                failure_stage_name(row.failure_stage), row.error_message, row.openssl_error);
        tls_conn_close(&conn);
        return -1;
    }
    (void)tls_shutdown_measure(&app->cfg, &conn, &row);
    tls_conn_close(&conn);
    return 0;
}

static int store_resumption_seed(app_t *app, SSL_SESSION *session) {
    if (!session || !SSL_SESSION_is_resumable(session)) return -1;
    int len = i2d_SSL_SESSION(session, NULL);
    if (len <= 0) return -1;
    unsigned char *buf = malloc((size_t)len);
    if (!buf) return -1;
    unsigned char *p = buf;
    if (i2d_SSL_SESSION(session, &p) != len) {
        free(buf);
        return -1;
    }
    free(app->resumption_seed_der);
    app->resumption_seed_der = buf;
    app->resumption_seed_der_len = (size_t)len;
    return 0;
}

static SSL_SESSION *dup_resumption_seed(const app_t *app) {
    if (!app->resumption_seed_der || app->resumption_seed_der_len == 0) return NULL;
    const unsigned char *p = app->resumption_seed_der;
    return d2i_SSL_SESSION(NULL, &p, (long)app->resumption_seed_der_len);
}

static int preflight_resumption(app_t *app) {
    session_store_clear(&app->sessions);
    app->sessions.callback_count = 0;

    probe_row_t row;
    probe_row_init(&row);
    tls_conn_t conn;
    if (open_tls_connection(app, &conn, &row, NULL, false, &app->sessions) != 0) {
        fprintf(stderr, "Resumption ticket-priming handshake failed at %s: %s %s\n",
                failure_stage_name(row.failure_stage), row.error_message, row.openssl_error);
        return -1;
    }
    if (perform_echo(app, &conn, &row, UINT64_MAX - 2) != 0) {
        fprintf(stderr, "Resumption ticket-priming echo failed at %s: %s %s\n",
                failure_stage_name(row.failure_stage), row.error_message, row.openssl_error);
        tls_conn_close(&conn);
        return -1;
    }
    (void)tls_shutdown_measure(&app->cfg, &conn, &row);
    tls_conn_close(&conn);

    SSL_SESSION *prime = session_store_take(&app->sessions);
    if (!prime || !SSL_SESSION_is_resumable(prime)) {
        if (prime) SSL_SESSION_free(prime);
        fprintf(stderr, "Resumption preflight failed: no resumable TLS 1.3 session ticket captured.\n");
        return -1;
    }
    if (store_resumption_seed(app, prime) != 0) {
        SSL_SESSION_free(prime);
        fprintf(stderr, "Resumption preflight failed: could not serialize the primed resumable session.\n");
        return -1;
    }

    probe_row_init(&row);
    if (open_tls_connection(app, &conn, &row, prime, true, &app->sessions) != 0) {
        SSL_SESSION_free(prime);
        fprintf(stderr, "Resumption validation handshake failed at %s: %s %s\n",
                failure_stage_name(row.failure_stage), row.error_message, row.openssl_error);
        return -1;
    }
    /* SSL_set_session() incremented its own reference; release the application copy. */
    SSL_SESSION_free(prime);

    if (perform_echo(app, &conn, &row, UINT64_MAX - 3) != 0) {
        fprintf(stderr, "Resumption validation echo failed at %s: %s %s\n",
                failure_stage_name(row.failure_stage), row.error_message, row.openssl_error);
        tls_conn_close(&conn);
        return -1;
    }
    (void)tls_shutdown_measure(&app->cfg, &conn, &row);
    tls_conn_close(&conn);

    if (strcmp(app->cfg.resumption_session_policy, "chain") == 0 &&
        (!app->sessions.latest || !SSL_SESSION_is_resumable(app->sessions.latest))) {
        fprintf(stderr, "Resumption validation failed: resumed connection did not yield a fresh resumable session ticket required by chain policy.\n");
        return -1;
    }
    if (strcmp(app->cfg.resumption_session_policy, "reuse_seed") == 0) {
        session_store_clear(&app->sessions); /* measured probes intentionally use fresh decodes of the primed ticket */
    }
    return 0;
}

static int prepare_record_connection(app_t *app, tls_conn_t *measurement_conn) {
    if (preflight_full(app) != 0) return -1;
    probe_row_t row;
    probe_row_init(&row);
    if (open_tls_connection(app, measurement_conn, &row, NULL, false, NULL) != 0) {
        fprintf(stderr, "Record measurement connection setup failed at %s: %s %s\n",
                failure_stage_name(row.failure_stage), row.error_message, row.openssl_error);
        return -1;
    }
    return 0;
}

static void csv_string(FILE *fp, const char *s) {
    if (!s) s = "";
    bool quote = strchr(s, ',') || strchr(s, '"') || strchr(s, '\n') || strchr(s, '\r');
    if (!quote) {
        fputs(s, fp);
        return;
    }
    fputc('"', fp);
    for (const char *p = s; *p; ++p) {
        if (*p == '"') fputc('"', fp);
        fputc(*p, fp);
    }
    fputc('"', fp);
}

static const char *optional_u64_text(uint64_t value, char buf[32]) {
    if (value == U64_NA) return "n/a";
    snprintf(buf, 32, "%llu", (unsigned long long)value);
    return buf;
}

static void csv_header(FILE *fp) {
    fputs("run_id,scenario,workload,repetition,probe_id,wall_time_utc_ns,elapsed_run_us,scheduled_elapsed_us,schedule_lag_us,missed_slots_before,connection_id,request_on_connection,reconnect,tls_version,cipher,group,peer_signature,session_reused,tcp_connect_us,tls_handshake_us,connection_establishment_us,send_us,time_to_first_byte_us,recv_us,app_rtt_us,tls_shutdown_us,probe_total_us,bytes_sent,bytes_received,payload_match,first_mismatch_offset,result_code,failure_stage,error_message,openssl_error\n", fp);
}

static void csv_u64(FILE *fp, uint64_t v) { fprintf(fp, "%llu", (unsigned long long)v); }

static void csv_row(app_t *app, const probe_row_t *r) {
    FILE *fp = app->csv;
#define SEP() fputc(',', fp)
    csv_string(fp, app->cli.run_id); SEP();
    csv_string(fp, app->cli.scenario); SEP();
    csv_string(fp, app->cli.workload_name); SEP();
    fprintf(fp, "%u", app->cli.repetition); SEP();
    csv_u64(fp, r->probe_id); SEP();
    csv_u64(fp, r->wall_time_utc_ns); SEP();
    csv_u64(fp, r->elapsed_run_us); SEP();
    csv_u64(fp, r->scheduled_elapsed_us); SEP();
    csv_u64(fp, r->schedule_lag_us); SEP();
    csv_u64(fp, r->missed_slots_before); SEP();
    if (r->connection_id) { csv_u64(fp, r->connection_id); } SEP();
    if (r->request_on_connection) { csv_u64(fp, r->request_on_connection); } SEP();
    fputs(r->reconnect ? "true" : "false", fp); SEP();
    csv_string(fp, r->tls_version); SEP();
    csv_string(fp, r->cipher); SEP();
    csv_string(fp, r->group); SEP();
    csv_string(fp, r->peer_signature); SEP();
    if (r->session_reused_valid) { fputs(r->session_reused ? "true" : "false", fp); } SEP();
    if (r->tcp_connect_us != U64_NA) { csv_u64(fp, r->tcp_connect_us); } SEP();
    if (r->tls_handshake_us != U64_NA) { csv_u64(fp, r->tls_handshake_us); } SEP();
    if (r->connection_establishment_us != U64_NA) { csv_u64(fp, r->connection_establishment_us); } SEP();
    if (r->send_us != U64_NA) { csv_u64(fp, r->send_us); } SEP();
    if (r->ttfb_us != U64_NA) { csv_u64(fp, r->ttfb_us); } SEP();
    if (r->recv_us != U64_NA) { csv_u64(fp, r->recv_us); } SEP();
    if (r->app_rtt_us != U64_NA) { csv_u64(fp, r->app_rtt_us); } SEP();
    if (r->tls_shutdown_us != U64_NA) { csv_u64(fp, r->tls_shutdown_us); } SEP();
    if (r->probe_total_us != U64_NA) { csv_u64(fp, r->probe_total_us); } SEP();
    fprintf(fp, "%zu", r->bytes_sent); SEP();
    fprintf(fp, "%zu", r->bytes_received); SEP();
    if (r->payload_match_valid) { fputs(r->payload_match ? "true" : "false", fp); } SEP();
    if (r->first_mismatch_offset >= 0) { fprintf(fp, "%ld", r->first_mismatch_offset); } SEP();
    fprintf(fp, "%d", r->result_code); SEP();
    csv_string(fp, failure_stage_name(r->failure_stage)); SEP();
    csv_string(fp, r->error_message); SEP();
    csv_string(fp, r->openssl_error);
    fputc('\n', fp);
    fflush(fp);
#undef SEP
}

static void finalize_row_timing(probe_row_t *row, uint64_t run_start_ns, uint64_t scheduled_ns,
                                uint64_t probe_start_ns, uint64_t probe_end_ns,
                                uint64_t missed_slots) {
    row->elapsed_run_us = elapsed_us(run_start_ns, probe_start_ns);
    row->scheduled_elapsed_us = elapsed_us(run_start_ns, scheduled_ns);
    row->schedule_lag_us = probe_start_ns > scheduled_ns ? elapsed_us(scheduled_ns, probe_start_ns) : 0;
    row->missed_slots_before = missed_slots;
    row->probe_total_us = elapsed_us(probe_start_ns, probe_end_ns);
}

static uint64_t advance_to_next_slot(uint64_t *slot, uint64_t run_start_ns, uint64_t period_ns,
                                     uint64_t now_ns) {
    uint64_t missed = 0;
    uint64_t target = run_start_ns + (*slot) * period_ns;
    if (now_ns > target && period_ns > 0) {
        uint64_t behind = now_ns - target;
        if (behind >= period_ns) {
            uint64_t skip = behind / period_ns;
            *slot += skip;
            missed = skip;
        }
    }
    return missed;
}

static int run_full_handshake(app_t *app, uint64_t run_start, uint64_t run_end, uint64_t period_ns) {
    uint64_t slot = 0, probe_id = 0;
    while (true) {
        uint64_t now = monotonic_ns();
        uint64_t missed = advance_to_next_slot(&slot, run_start, period_ns, now);
        uint64_t scheduled = run_start + slot * period_ns;
        if (scheduled >= run_end) break;
        sleep_until_ns(scheduled);
        uint64_t start = monotonic_ns();
        if (start >= run_end) break;

        probe_row_t row;
        probe_row_init(&row);
        row.probe_id = probe_id++;
        row.wall_time_utc_ns = realtime_ns();
        tls_conn_t conn;
        if (open_tls_connection(app, &conn, &row, NULL, false, NULL) == 0) {
            if (perform_echo(app, &conn, &row, row.probe_id) != 0) {
                row.result_code = row.result_code == 0 ? -2 : row.result_code;
            }
            if (tls_shutdown_measure(&app->cfg, &conn, &row) != 0 && row.result_code == 0) {
                row.result_code = -2;
            }
            copy_conn_metadata(&row, &conn);
            tls_conn_close(&conn);
        } else {
            row.result_code = -2;
        }
        uint64_t end = monotonic_ns();
        finalize_row_timing(&row, run_start, scheduled, start, end, missed);
        csv_row(app, &row);
        if (app->cfg.stdout_progress) {
            char hs[32], rtt[32];
            printf("[%s] probe=%llu result=%d handshake_us=%s app_rtt_us=%s\n",
                   app->cli.workload_name, (unsigned long long)row.probe_id, row.result_code,
                   optional_u64_text(row.tls_handshake_us, hs),
                   optional_u64_text(row.app_rtt_us, rtt));
        }
        ++slot;
    }
    return 0;
}

static int run_resumption(app_t *app, uint64_t run_start, uint64_t run_end, uint64_t period_ns) {
    uint64_t slot = 0, probe_id = 0;
    bool chain_policy = strcmp(app->cfg.resumption_session_policy, "chain") == 0;

    while (true) {
        uint64_t now = monotonic_ns();
        uint64_t missed = advance_to_next_slot(&slot, run_start, period_ns, now);
        uint64_t scheduled = run_start + slot * period_ns;
        if (scheduled >= run_end) break;
        sleep_until_ns(scheduled);
        uint64_t start = monotonic_ns();
        if (start >= run_end) break;

        probe_row_t row;
        probe_row_init(&row);
        row.probe_id = probe_id++;
        row.wall_time_utc_ns = realtime_ns();

        SSL_SESSION *session = chain_policy ? session_store_take(&app->sessions) : dup_resumption_seed(app);
        if (!session || !SSL_SESSION_is_resumable(session)) {
            if (session) SSL_SESSION_free(session);
            row.result_code = -2;
            row.failure_stage = FAIL_SESSION_TICKET;
            snprintf(row.error_message, sizeof(row.error_message),
                     "no resumable session available for scheduled probe (policy=%s)",
                     app->cfg.resumption_session_policy);
        } else {
            tls_conn_t conn;
            session_store_t *capture = chain_policy ? &app->sessions : NULL;
            if (open_tls_connection(app, &conn, &row, session, true, capture) == 0) {
                /* SSL_set_session() owns a separate reference now. */
                SSL_SESSION_free(session);
                session = NULL;
                if (perform_echo(app, &conn, &row, row.probe_id) != 0) {
                    row.result_code = row.result_code == 0 ? -2 : row.result_code;
                }
                if (tls_shutdown_measure(&app->cfg, &conn, &row) != 0 && row.result_code == 0) {
                    row.result_code = -2;
                }
                copy_conn_metadata(&row, &conn);
                tls_conn_close(&conn);
                if (chain_policy && row.result_code == 0 &&
                    (!app->sessions.latest || !SSL_SESSION_is_resumable(app->sessions.latest))) {
                    row.result_code = -2;
                    row.failure_stage = FAIL_SESSION_TICKET;
                    snprintf(row.error_message, sizeof(row.error_message),
                             "resumed connection yielded no fresh resumable TLS 1.3 session");
                }
            } else {
                SSL_SESSION_free(session);
                session = NULL;
                row.result_code = -2;
            }
        }

        uint64_t end = monotonic_ns();
        finalize_row_timing(&row, run_start, scheduled, start, end, missed);
        csv_row(app, &row);
        if (app->cfg.stdout_progress) {
            char hs[32], rtt[32];
            printf("[%s] probe=%llu result=%d reused=%s handshake_us=%s app_rtt_us=%s\n",
                   app->cli.workload_name, (unsigned long long)row.probe_id, row.result_code,
                   row.session_reused_valid ? (row.session_reused ? "true" : "false") : "n/a",
                   optional_u64_text(row.tls_handshake_us, hs),
                   optional_u64_text(row.app_rtt_us, rtt));
        }
        /* chain mode cannot continue once its fresh-ticket chain is lost; reuse_seed remains measurable. */
        if (chain_policy && row.result_code != 0 && !app->sessions.latest) {
            fprintf(stderr, "Resumption chain lost; stopping run because no fresh session remains. Use reuse_seed policy for failure-continuous pilot runs.\\n");
            return -1;
        }
        ++slot;
    }
    return 0;
}

static int record_reconnect(app_t *app, tls_conn_t *conn, probe_row_t *row) {
    tls_conn_close(conn);
    if (!app->cfg.record_reconnect_on_failure) {
        return -1;
    }
    if (app->cfg.record_reconnect_backoff_ms > 0) {
        sleep_ms(app->cfg.record_reconnect_backoff_ms);
    }
    probe_row_t connect_row;
    probe_row_init(&connect_row);
    if (open_tls_connection(app, conn, &connect_row, NULL, false, NULL) != 0) {
        row->tcp_connect_us = connect_row.tcp_connect_us;
        row->tls_handshake_us = connect_row.tls_handshake_us;
        row->connection_establishment_us = connect_row.connection_establishment_us;
        row->failure_stage = connect_row.failure_stage;
        snprintf(row->error_message, sizeof(row->error_message), "%s", connect_row.error_message);
        snprintf(row->openssl_error, sizeof(row->openssl_error), "%s", connect_row.openssl_error);
        return -1;
    }
    row->reconnect = true;
    row->tcp_connect_us = connect_row.tcp_connect_us;
    row->tls_handshake_us = connect_row.tls_handshake_us;
    row->connection_establishment_us = connect_row.connection_establishment_us;
    copy_conn_metadata(row, conn);
    return 0;
}

static int run_record(app_t *app, tls_conn_t *conn, uint64_t run_start, uint64_t run_end, uint64_t period_ns) {
    uint64_t slot = 0, probe_id = 0;
    bool connected = (conn->ssl != NULL);

    while (true) {
        uint64_t now = monotonic_ns();
        uint64_t missed = advance_to_next_slot(&slot, run_start, period_ns, now);
        uint64_t scheduled = run_start + slot * period_ns;
        if (scheduled >= run_end) break;
        sleep_until_ns(scheduled);
        uint64_t start = monotonic_ns();
        if (start >= run_end) break;

        probe_row_t row;
        probe_row_init(&row);
        row.probe_id = probe_id++;
        row.wall_time_utc_ns = realtime_ns();

        if (!connected) {
            if (record_reconnect(app, conn, &row) == 0) {
                connected = true;
            } else {
                row.result_code = -2;
            }
        }

        if (connected) {
            copy_conn_metadata(&row, conn);
            if (perform_echo(app, conn, &row, row.probe_id) != 0) {
                row.result_code = row.result_code == 0 ? -2 : row.result_code;
                copy_conn_metadata(&row, conn);
                tls_conn_close(conn);
                connected = false;
            } else {
                copy_conn_metadata(&row, conn);
            }
        }

        uint64_t end = monotonic_ns();
        finalize_row_timing(&row, run_start, scheduled, start, end, missed);
        csv_row(app, &row);
        if (app->cfg.stdout_progress) {
            char rtt[32];
            printf("[%s] probe=%llu result=%d reconnect=%s app_rtt_us=%s\n",
                   app->cli.workload_name, (unsigned long long)row.probe_id, row.result_code,
                   row.reconnect ? "true" : "false",
                   optional_u64_text(row.app_rtt_us, rtt));
        }
        ++slot;
    }

    if (connected) {
        probe_row_t shutdown_row;
        probe_row_init(&shutdown_row);
        (void)tls_shutdown_measure(&app->cfg, conn, &shutdown_row);
    }
    tls_conn_close(conn);
    return 0;
}

static void json_escape(FILE *fp, const char *s) {
    fputc('"', fp);
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        switch (*p) {
            case '"': fputs("\\\"", fp); break;
            case '\\': fputs("\\\\", fp); break;
            case '\n': fputs("\\n", fp); break;
            case '\r': fputs("\\r", fp); break;
            case '\t': fputs("\\t", fp); break;
            default:
                if (*p < 0x20) fprintf(fp, "\\u%04x", *p);
                else fputc(*p, fp);
        }
    }
    fputc('"', fp);
}

static int sha256_file(const char *path, char out_hex[65]) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { fclose(fp); return -1; }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) { EVP_MD_CTX_free(ctx); fclose(fp); return -1; }
    unsigned char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (EVP_DigestUpdate(ctx, buf, n) != 1) { EVP_MD_CTX_free(ctx); fclose(fp); return -1; }
    }
    if (ferror(fp)) { EVP_MD_CTX_free(ctx); fclose(fp); return -1; }
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    if (EVP_DigestFinal_ex(ctx, md, &mdlen) != 1) { EVP_MD_CTX_free(ctx); fclose(fp); return -1; }
    EVP_MD_CTX_free(ctx);
    fclose(fp);
    for (unsigned i = 0; i < mdlen; ++i) snprintf(out_hex + 2 * i, 65 - 2 * i, "%02x", md[i]);
    out_hex[2 * mdlen] = '\0';
    return 0;
}

static int hash_effective_config(const app_t *app, char out_hex[65]) {
    char pattern_hex[MAX_PATTERN * 2 + 1];
    pattern_hex[0] = '\0';
    for (size_t i = 0; i < app->cfg.payload_pattern_len; ++i) {
        snprintf(pattern_hex + 2 * i, sizeof(pattern_hex) - 2 * i, "%02x", app->cfg.payload_pattern[i]);
    }
    char canonical[4096];
    int n = snprintf(canonical, sizeof(canonical),
        "client_version=%s\n"
        "scenario=%s\nworkload=%s\nrepetition=%u\n"
        "tls.verify_peer=%d\ntls.verify_hostname=%d\ntls.strict_shutdown=%d\n"
        "tls.ciphersuite=%s\ntls.group=%s\ntls.signature_algorithm=%s\n"
        "run.duration_s=%llu\nrun.probe_interval_ms=%llu\n"
        "timeouts.tcp_connect_ms=%llu\ntimeouts.tls_handshake_ms=%llu\ntimeouts.io_ms=%llu\n"
        "payload.size_bytes=%zu\npayload.mode=%s\npayload.seed=%llu\npayload.pattern_hex=%s\n"
        "resumption.session_policy=%s\n"
        "socket.tcp_nodelay=%d\nrecord.reconnect_on_failure=%d\nrecord.reconnect_backoff_ms=%llu\n",
        CLIENT_VERSION, app->cli.scenario, app->cli.workload_name, app->cli.repetition,
        app->cfg.verify_peer, app->cfg.verify_hostname, app->cfg.strict_shutdown,
        app->cfg.ciphersuite, app->cfg.group, app->cfg.signature_algorithm,
        (unsigned long long)app->cfg.duration_s, (unsigned long long)app->cfg.probe_interval_ms,
        (unsigned long long)app->cfg.tcp_connect_timeout_ms,
        (unsigned long long)app->cfg.tls_handshake_timeout_ms,
        (unsigned long long)app->cfg.io_timeout_ms,
        app->cfg.payload_size, app->cfg.payload_mode, (unsigned long long)app->cfg.payload_seed, pattern_hex,
        app->cfg.resumption_session_policy,
        app->cfg.tcp_nodelay, app->cfg.record_reconnect_on_failure,
        (unsigned long long)app->cfg.record_reconnect_backoff_ms);
    if (n < 0 || (size_t)n >= sizeof(canonical)) return -1;

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    if (EVP_Digest(canonical, (size_t)n, md, &mdlen, EVP_sha256(), NULL) != 1) return -1;
    for (unsigned i = 0; i < mdlen; ++i) snprintf(out_hex + 2 * i, 65 - 2 * i, "%02x", md[i]);
    out_hex[2 * mdlen] = '\0';
    return 0;
}

static int write_metadata(const app_t *app) {
    FILE *fp = fopen(app->metadata_path, "wx");
    if (!fp) {
        fprintf(stderr, "Cannot create metadata %s: %s\n", app->metadata_path, strerror(errno));
        return -1;
    }

    char exe_path[PATH_MAX] = {0};
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len > 0) exe_path[len] = '\0';
    char bin_hash[65] = "unavailable";
    if (len <= 0 || sha256_file(exe_path, bin_hash) != 0) snprintf(bin_hash, sizeof(bin_hash), "%s", "unavailable");
    char cfg_hash[65] = "unavailable";
    if (hash_effective_config(app, cfg_hash) != 0) snprintf(cfg_hash, sizeof(cfg_hash), "%s", "unavailable");

    fprintf(fp, "{\n  \"run_id\": "); json_escape(fp, app->cli.run_id);
    fprintf(fp, ",\n  \"scenario\": "); json_escape(fp, app->cli.scenario);
    fprintf(fp, ",\n  \"workload\": "); json_escape(fp, app->cli.workload_name);
    fprintf(fp, ",\n  \"repetition\": %u", app->cli.repetition);
    fprintf(fp, ",\n  \"client_version\": "); json_escape(fp, CLIENT_VERSION);
    fprintf(fp, ",\n  \"client_git_commit\": "); json_escape(fp, CLIENT_GIT_COMMIT);
    fprintf(fp, ",\n  \"client_binary_sha256\": "); json_escape(fp, bin_hash);
    fprintf(fp, ",\n  \"openssl_compile_version\": "); json_escape(fp, OPENSSL_VERSION_TEXT);
    fprintf(fp, ",\n  \"openssl_runtime_version\": "); json_escape(fp, OpenSSL_version(OPENSSL_VERSION));
    fprintf(fp, ",\n  \"configured_duration_s\": %llu", (unsigned long long)app->cfg.duration_s);
    fprintf(fp, ",\n  \"configured_probe_interval_ms\": %llu", (unsigned long long)app->cfg.probe_interval_ms);
    fprintf(fp, ",\n  \"timeout_tcp_connect_ms\": %llu", (unsigned long long)app->cfg.tcp_connect_timeout_ms);
    fprintf(fp, ",\n  \"timeout_tls_handshake_ms\": %llu", (unsigned long long)app->cfg.tls_handshake_timeout_ms);
    fprintf(fp, ",\n  \"timeout_io_ms\": %llu", (unsigned long long)app->cfg.io_timeout_ms);
    fprintf(fp, ",\n  \"payload_size\": %zu", app->cfg.payload_size);
    fprintf(fp, ",\n  \"payload_mode\": "); json_escape(fp, app->cfg.payload_mode);
    fprintf(fp, ",\n  \"resumption_session_policy\": "); json_escape(fp, app->cfg.resumption_session_policy);
    fprintf(fp, ",\n  \"expected_tls_version\": \"TLSv1.3\"");
    fprintf(fp, ",\n  \"expected_ciphersuite\": "); json_escape(fp, app->cfg.ciphersuite);
    fprintf(fp, ",\n  \"expected_group\": "); json_escape(fp, app->cfg.group);
    fprintf(fp, ",\n  \"expected_signature_algorithm\": "); json_escape(fp, app->cfg.signature_algorithm);
    fprintf(fp, ",\n  \"certificate_verification_enabled\": %s", app->cfg.verify_peer ? "true" : "false");
    fprintf(fp, ",\n  \"effective_non_sensitive_config_sha256\": "); json_escape(fp, cfg_hash);
    fprintf(fp, "\n}\n");
    fclose(fp);
    return 0;
}

static int open_outputs(app_t *app) {
    if (mkdir_p(app->cfg.output_directory) != 0) {
        fprintf(stderr, "Cannot create output directory %s: %s\n", app->cfg.output_directory, strerror(errno));
        return -1;
    }
    int n1 = snprintf(app->csv_path, sizeof(app->csv_path), "%s/%s_%s_%s_r%u_%s.csv",
                      app->cfg.output_directory, app->cfg.csv_prefix, app->cli.scenario,
                      app->cli.workload_name, app->cli.repetition, app->cli.run_id);
    int n2 = snprintf(app->metadata_path, sizeof(app->metadata_path), "%s/%s_%s_%s_r%u_%s.metadata.json",
                      app->cfg.output_directory, app->cfg.csv_prefix, app->cli.scenario,
                      app->cli.workload_name, app->cli.repetition, app->cli.run_id);
    if (n1 < 0 || n2 < 0 || (size_t)n1 >= sizeof(app->csv_path) || (size_t)n2 >= sizeof(app->metadata_path)) {
        fprintf(stderr, "Output path too long.\n");
        return -1;
    }
    app->csv = fopen(app->csv_path, "wx");
    if (!app->csv) {
        fprintf(stderr, "Cannot create CSV %s: %s\n", app->csv_path, strerror(errno));
        return -1;
    }
    csv_header(app->csv);
    fflush(app->csv);
    return 0;
}

static int check_openssl_runtime(void) {
    unsigned long v = OpenSSL_version_num();
    if (v < 0x30500000L) {
        fprintf(stderr, "OpenSSL 3.5 or newer is required; runtime is %s\n", OpenSSL_version(OPENSSL_VERSION));
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    app_t app;
    memset(&app, 0, sizeof(app));
    config_defaults(&app.cfg);
    if (parse_cli(argc, argv, &app.cli) != 0) return 2;

    char err[MAX_ERROR];
    if (load_config_file(app.cli.config_path, &app.cfg, err, sizeof(err)) != 0) {
        fprintf(stderr, "Configuration error: %s\n", err);
        return 2;
    }
    apply_cli_overrides(&app);
    if (validate_config(&app.cfg, err, sizeof(err)) != 0) {
        fprintf(stderr, "Configuration error: %s\n", err);
        return 2;
    }
    if (!app.cli.run_id_set) generate_run_id(app.cli.run_id, sizeof(app.cli.run_id));

    if (check_openssl_runtime() != 0) return 2;

    app.ssl_ctx = make_ssl_ctx(&app.cfg, err, sizeof(err));
    if (!app.ssl_ctx) {
        fprintf(stderr, "TLS context initialization failed: %s\n", err);
        return 2;
    }

    app.payload = malloc(app.cfg.payload_size);
    if (!app.payload) {
        fprintf(stderr, "Cannot allocate payload buffer of %zu bytes.\n", app.cfg.payload_size);
        SSL_CTX_free(app.ssl_ctx);
        return 2;
    }

    printf("Reference client %s\n", CLIENT_VERSION);
    printf("OpenSSL runtime: %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("Scenario: %s\nWorkload: %s\nRepetition: %u\nRun ID: %s\n",
           app.cli.scenario, app.cli.workload_name, app.cli.repetition, app.cli.run_id);
    printf("Duration: %llu s, probe interval: %llu ms, payload: %zu bytes\n",
           (unsigned long long)app.cfg.duration_s,
           (unsigned long long)app.cfg.probe_interval_ms,
           app.cfg.payload_size);

    int rc = 0;
    tls_conn_t record_conn;
    memset(&record_conn, 0, sizeof(record_conn));
    record_conn.fd = -1;

    if (app.cli.workload == WORKLOAD_FULL_HANDSHAKE) {
        rc = preflight_full(&app);
    } else if (app.cli.workload == WORKLOAD_RESUMPTION) {
        rc = preflight_resumption(&app);
    } else {
        rc = prepare_record_connection(&app, &record_conn);
    }
    if (rc != 0) {
        fprintf(stderr, "Preflight failed; measured run will not start.\n");
        tls_conn_close(&record_conn);
        session_store_clear(&app.sessions);
        free(app.resumption_seed_der);
        free(app.payload);
        SSL_CTX_free(app.ssl_ctx);
        return 3;
    }

    if (open_outputs(&app) != 0) {
        tls_conn_close(&record_conn);
        session_store_clear(&app.sessions);
        free(app.resumption_seed_der);
        free(app.payload);
        SSL_CTX_free(app.ssl_ctx);
        return 2;
    }
    if (write_metadata(&app) != 0) {
        fclose(app.csv);
        unlink(app.csv_path);
        tls_conn_close(&record_conn);
        session_store_clear(&app.sessions);
        free(app.resumption_seed_der);
        free(app.payload);
        SSL_CTX_free(app.ssl_ctx);
        return 2;
    }

    printf("CSV: %s\nMetadata: %s\n", app.csv_path, app.metadata_path);

    uint64_t run_start = monotonic_ns();
    uint64_t run_end = run_start + app.cfg.duration_s * NS_PER_S;
    uint64_t period_ns = app.cfg.probe_interval_ms * NS_PER_MS;

    if (app.cli.workload == WORKLOAD_FULL_HANDSHAKE) {
        rc = run_full_handshake(&app, run_start, run_end, period_ns);
    } else if (app.cli.workload == WORKLOAD_RESUMPTION) {
        rc = run_resumption(&app, run_start, run_end, period_ns);
    } else {
        rc = run_record(&app, &record_conn, run_start, run_end, period_ns);
    }

    fclose(app.csv);
    session_store_clear(&app.sessions);
    free(app.resumption_seed_der);
    free(app.payload);
    SSL_CTX_free(app.ssl_ctx);
    return rc == 0 ? 0 : 4;
}
