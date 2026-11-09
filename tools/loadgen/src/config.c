#include "tls_loadgen.h"

#include <ctype.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) {
        ++s;
    }
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) {
        --end;
    }
    *end = '\0';
    return s;
}

static int parse_bool(const char *s, bool *out) {
    if (!s || !out) return -1;
    if (strcasecmp(s, "true") == 0 || strcmp(s, "1") == 0 || strcasecmp(s, "yes") == 0 || strcasecmp(s, "on") == 0) {
        *out = true;
        return 0;
    }
    if (strcasecmp(s, "false") == 0 || strcmp(s, "0") == 0 || strcasecmp(s, "no") == 0 || strcasecmp(s, "off") == 0) {
        *out = false;
        return 0;
    }
    return -1;
}

static int parse_u64(const char *s, uint64_t *out) {
    if (!s || !*s || !out) return -1;
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno != 0 || !end || *end != '\0') return -1;
    *out = (uint64_t)v;
    return 0;
}

static int parse_u32(const char *s, uint32_t *out) {
    uint64_t v = 0;
    if (parse_u64(s, &v) != 0 || v > UINT32_MAX) return -1;
    *out = (uint32_t)v;
    return 0;
}

static int parse_u16(const char *s, uint16_t *out) {
    uint64_t v = 0;
    if (parse_u64(s, &v) != 0 || v > UINT16_MAX) return -1;
    *out = (uint16_t)v;
    return 0;
}

static int parse_double_value(const char *s, double *out) {
    if (!s || !*s || !out) return -1;
    errno = 0;
    char *end = NULL;
    double v = strtod(s, &end);
    if (errno != 0 || !end || *end != '\0') return -1;
    *out = v;
    return 0;
}

static int parse_workload(const char *s, workload_t *out) {
    if (strcmp(s, "full-handshake") == 0 || strcmp(s, "full") == 0) {
        *out = WORKLOAD_FULL;
    } else if (strcmp(s, "resumption") == 0 || strcmp(s, "resume") == 0) {
        *out = WORKLOAD_RESUMPTION;
    } else if (strcmp(s, "record") == 0) {
        *out = WORKLOAD_RECORD;
    } else {
        return -1;
    }
    return 0;
}

static int parse_mode(const char *s, generation_mode_t *out) {
    if (strcmp(s, "benign") == 0) {
        *out = MODE_BENIGN;
    } else if (strcmp(s, "flood") == 0) {
        *out = MODE_FLOOD;
    } else {
        return -1;
    }
    return 0;
}

static int parse_backend(const char *s, backend_kind_t *out) {
    if (strcmp(s, "posix") == 0) {
        *out = BACKEND_POSIX;
    } else if (strcmp(s, "fstack") == 0 || strcmp(s, "dpdk") == 0) {
        *out = BACKEND_FSTACK;
    } else {
        return -1;
    }
    return 0;
}

void config_defaults(config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->target_address, sizeof(cfg->target_address), "172.10.10.150");
    cfg->target_port = 4433;
    snprintf(cfg->target_mac, sizeof(cfg->target_mac), "00:04:9f:09:68:bd");
    snprintf(cfg->source_address, sizeof(cfg->source_address), "172.10.10.50");
    snprintf(cfg->netmask, sizeof(cfg->netmask), "255.255.255.0");
    snprintf(cfg->source_interface, sizeof(cfg->source_interface), "enp1s0");
    cfg->mtu = 1500;
    cfg->tcp_nodelay = true;

    snprintf(cfg->ca_file, sizeof(cfg->ca_file), "~/certificates/server.crt");
    snprintf(cfg->server_name, sizeof(cfg->server_name), "tls-echo-server");
    cfg->verify_peer = true;
    cfg->verify_hostname = false;
    snprintf(cfg->ciphersuite, sizeof(cfg->ciphersuite), "TLS_AES_128_GCM_SHA256");
    snprintf(cfg->group, sizeof(cfg->group), "P-256");
    snprintf(cfg->signature_algorithm, sizeof(cfg->signature_algorithm), "ecdsa_secp256r1_sha256");

    cfg->workload = WORKLOAD_FULL;
    cfg->mode = MODE_BENIGN;
    snprintf(cfg->scenario, sizeof(cfg->scenario), "A");
    cfg->rate_per_s = 10.0;
    cfg->duration_s = 30;
    cfg->max_inflight = 512;
    cfg->max_release_burst = 4096;
    cfg->drain_timeout_ms = 10000;

    cfg->tcp_connect_timeout_ms = 5000;
    cfg->tls_handshake_timeout_ms = 5000;
    cfg->io_timeout_ms = 5000;

    cfg->payload_size = 1024;
    cfg->payload_pattern = 0xa5;
    cfg->full_echo_after_handshake = false;
    snprintf(cfg->resumption_policy, sizeof(cfg->resumption_policy), "reuse_seed");
    cfg->resumption_pool_size = 32;
    cfg->resumption_wait_for_fresh_ticket = true;
    cfg->record_connections = 32;
    cfg->record_max_pending_releases = 4096;
    cfg->record_reconnect = true;
    cfg->record_reconnect_backoff_ms = 1000;

    snprintf(cfg->output_directory, sizeof(cfg->output_directory), "./results");
    snprintf(cfg->fstack_conf, sizeof(cfg->fstack_conf), "./config/f-stack.conf");
    cfg->fstack_proc_id = 0;
    cfg->stdout_progress = true;
}

static int set_key(config_t *cfg, const char *key, const char *value, char *err, size_t errlen) {
#define SETSTR(field) do { snprintf(cfg->field, sizeof(cfg->field), "%s", value); return 0; } while (0)
#define SETBOOL(field) do { if (parse_bool(value, &cfg->field) != 0) goto bad; return 0; } while (0)
#define SETU64(field) do { if (parse_u64(value, &cfg->field) != 0) goto bad; return 0; } while (0)
#define SETU32(field) do { if (parse_u32(value, &cfg->field) != 0) goto bad; return 0; } while (0)
#define SETU16(field) do { if (parse_u16(value, &cfg->field) != 0) goto bad; return 0; } while (0)

    if (strcmp(key, "target.address") == 0) SETSTR(target_address);
    if (strcmp(key, "target.port") == 0) SETU16(target_port);
    if (strcmp(key, "target.mac") == 0) SETSTR(target_mac);
    if (strcmp(key, "network.source_address") == 0) SETSTR(source_address);
    if (strcmp(key, "network.netmask") == 0) SETSTR(netmask);
    if (strcmp(key, "network.interface") == 0) SETSTR(source_interface);
    if (strcmp(key, "network.mtu") == 0) SETU16(mtu);
    if (strcmp(key, "network.tcp_nodelay") == 0) SETBOOL(tcp_nodelay);

    if (strcmp(key, "tls.ca_file") == 0) SETSTR(ca_file);
    if (strcmp(key, "tls.server_name") == 0) SETSTR(server_name);
    if (strcmp(key, "tls.verify_peer") == 0) SETBOOL(verify_peer);
    if (strcmp(key, "tls.verify_hostname") == 0) SETBOOL(verify_hostname);
    if (strcmp(key, "tls.ciphersuite") == 0) SETSTR(ciphersuite);
    if (strcmp(key, "tls.group") == 0) SETSTR(group);
    if (strcmp(key, "tls.signature_algorithm") == 0) SETSTR(signature_algorithm);

    if (strcmp(key, "run.workload") == 0) {
        if (parse_workload(value, &cfg->workload) != 0) goto bad;
        return 0;
    }
    if (strcmp(key, "run.mode") == 0) {
        if (parse_mode(value, &cfg->mode) != 0) goto bad;
        return 0;
    }
    if (strcmp(key, "run.scenario") == 0) SETSTR(scenario);
    if (strcmp(key, "run.rate_per_s") == 0) {
        if (parse_double_value(value, &cfg->rate_per_s) != 0) goto bad;
        return 0;
    }
    if (strcmp(key, "run.duration_s") == 0) SETU64(duration_s);
    if (strcmp(key, "run.max_inflight") == 0) SETU32(max_inflight);
    if (strcmp(key, "run.max_release_burst") == 0) SETU32(max_release_burst);
    if (strcmp(key, "run.drain_timeout_ms") == 0) SETU64(drain_timeout_ms);

    if (strcmp(key, "timeout.tcp_connect_ms") == 0) SETU64(tcp_connect_timeout_ms);
    if (strcmp(key, "timeout.tls_handshake_ms") == 0) SETU64(tls_handshake_timeout_ms);
    if (strcmp(key, "timeout.io_ms") == 0) SETU64(io_timeout_ms);

    if (strcmp(key, "payload.size") == 0) {
        uint64_t v = 0;
        if (parse_u64(value, &v) != 0 || v > SIZE_MAX) goto bad;
        cfg->payload_size = (size_t)v;
        return 0;
    }
    if (strcmp(key, "payload.pattern_hex") == 0) {
        errno = 0;
        char *end = NULL;
        unsigned long v = strtoul(value, &end, 16);
        if (errno != 0 || !end || *end != '\0' || v > 255) goto bad;
        cfg->payload_pattern = (uint8_t)v;
        return 0;
    }
    if (strcmp(key, "full.echo_after_handshake") == 0) SETBOOL(full_echo_after_handshake);
    if (strcmp(key, "resumption.session_policy") == 0) SETSTR(resumption_policy);
    if (strcmp(key, "resumption.pool_size") == 0) SETU32(resumption_pool_size);
    if (strcmp(key, "resumption.wait_for_fresh_ticket") == 0) SETBOOL(resumption_wait_for_fresh_ticket);
    if (strcmp(key, "record.connections") == 0) SETU32(record_connections);
    if (strcmp(key, "record.max_pending_releases") == 0) SETU32(record_max_pending_releases);
    if (strcmp(key, "record.reconnect") == 0) SETBOOL(record_reconnect);
    if (strcmp(key, "record.reconnect_backoff_ms") == 0) SETU64(record_reconnect_backoff_ms);

    if (strcmp(key, "output.directory") == 0) SETSTR(output_directory);
    if (strcmp(key, "output.run_id") == 0) SETSTR(run_id);
    if (strcmp(key, "output.stdout_progress") == 0) SETBOOL(stdout_progress);
    if (strcmp(key, "fstack.conf") == 0) SETSTR(fstack_conf);
    if (strcmp(key, "fstack.proc_id") == 0) {
        uint32_t v = 0;
        if (parse_u32(value, &v) != 0) goto bad;
        cfg->fstack_proc_id = v;
        return 0;
    }

    snprintf(err, errlen, "unknown configuration key: %.200s", key);
    return -1;

bad:
    snprintf(err, errlen, "invalid value for %.200s: %.200s", key, value);
    return -1;
#undef SETSTR
#undef SETBOOL
#undef SETU64
#undef SETU32
#undef SETU16
}

int config_load(const char *path, config_t *cfg, char *err, size_t errlen) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        snprintf(err, errlen, "cannot open config %.700s: %.250s", path, strerror(errno));
        return -1;
    }
    char line[2048];
    unsigned line_no = 0;
    while (fgets(line, sizeof(line), fp)) {
        ++line_no;
        char *text = trim(line);
        if (*text == '\0' || *text == '#') continue;
        char *eq = strchr(text, '=');
        if (!eq) {
            snprintf(err, errlen, "%.700s:%u: expected key=value", path, line_no);
            fclose(fp);
            return -1;
        }
        *eq = '\0';
        char *key = trim(text);
        char *value = trim(eq + 1);
        char *comment = strchr(value, '#');
        if (comment) {
            *comment = '\0';
            value = trim(value);
        }
        if (*key == '\0') {
            snprintf(err, errlen, "%.700s:%u: empty key", path, line_no);
            fclose(fp);
            return -1;
        }
        if (set_key(cfg, key, value, err, errlen) != 0) {
            char detail[TLSGEN_MAX_ERR];
            snprintf(detail, sizeof(detail), "%s", err);
            snprintf(err, errlen, "%.600s:%u: %.350s", path, line_no, detail);
            fclose(fp);
            return -1;
        }
    }
    if (ferror(fp)) {
        snprintf(err, errlen, "error reading config %.700s", path);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

void print_usage(FILE *out, const char *argv0) {
    fprintf(out,
        "Usage: %s --config FILE --backend posix|fstack [overrides]\n"
        "\n"
        "Run identity / workload overrides:\n"
        "  --scenario A|B|C|D|E\n"
        "  --workload full-handshake|resumption|record\n"
        "  --mode benign|flood\n"
        "  --rate OPERATIONS_PER_SECOND\n"
        "  --duration SECONDS\n"
        "  --max-inflight N\n"
        "  --record-connections N\n"
        "  --target IPv4\n"
        "  --port PORT\n"
        "  --output-dir DIR\n"
        "  --run-id ID\n"
        "  --fstack-conf FILE\n"
        "  --version\n"
        "\n"
        "The benign/flood mode is metadata and policy identity; both modes use the same\n"
        "TLS state machine and explicit open-loop rate scheduler.\n",
        argv0);
}

int cli_parse(int argc, char **argv, cli_t *cli, char *err, size_t errlen) {
    memset(cli, 0, sizeof(*cli));
    static const struct option options[] = {
        {"config", required_argument, NULL, 'c'},
        {"backend", required_argument, NULL, 'b'},
        {"scenario", required_argument, NULL, 's'},
        {"workload", required_argument, NULL, 'w'},
        {"mode", required_argument, NULL, 'm'},
        {"rate", required_argument, NULL, 'r'},
        {"duration", required_argument, NULL, 'd'},
        {"max-inflight", required_argument, NULL, 'i'},
        {"record-connections", required_argument, NULL, 'n'},
        {"target", required_argument, NULL, 't'},
        {"port", required_argument, NULL, 'p'},
        {"output-dir", required_argument, NULL, 'o'},
        {"run-id", required_argument, NULL, 'u'},
        {"fstack-conf", required_argument, NULL, 'f'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int ch;
    while ((ch = getopt_long(argc, argv, "c:b:s:w:m:r:d:i:n:t:p:o:u:f:h", options, NULL)) != -1) {
        switch (ch) {
            case 'c': snprintf(cli->config_path, sizeof(cli->config_path), "%s", optarg); break;
            case 'b':
                if (parse_backend(optarg, &cli->backend) != 0) goto bad_value;
                cli->backend_set = true;
                break;
            case 's': snprintf(cli->scenario, sizeof(cli->scenario), "%s", optarg); cli->scenario_set = true; break;
            case 'w': if (parse_workload(optarg, &cli->workload) != 0) goto bad_value; cli->workload_set = true; break;
            case 'm': if (parse_mode(optarg, &cli->mode) != 0) goto bad_value; cli->mode_set = true; break;
            case 'r': if (parse_double_value(optarg, &cli->rate_per_s) != 0) goto bad_value; cli->rate_set = true; break;
            case 'd': if (parse_u64(optarg, &cli->duration_s) != 0) goto bad_value; cli->duration_set = true; break;
            case 'i': if (parse_u32(optarg, &cli->max_inflight) != 0) goto bad_value; cli->max_inflight_set = true; break;
            case 'n': if (parse_u32(optarg, &cli->record_connections) != 0) goto bad_value; cli->record_connections_set = true; break;
            case 't': snprintf(cli->target_address, sizeof(cli->target_address), "%s", optarg); cli->target_set = true; break;
            case 'p': if (parse_u16(optarg, &cli->target_port) != 0) goto bad_value; cli->port_set = true; break;
            case 'o': snprintf(cli->output_directory, sizeof(cli->output_directory), "%s", optarg); cli->output_set = true; break;
            case 'u': snprintf(cli->run_id, sizeof(cli->run_id), "%s", optarg); cli->run_id_set = true; break;
            case 'f': snprintf(cli->fstack_conf, sizeof(cli->fstack_conf), "%s", optarg); cli->fstack_conf_set = true; break;
            case 'h': print_usage(stdout, argv[0]); exit(EXIT_SUCCESS);
            default:
                snprintf(err, errlen, "invalid command line; use --help");
                return -1;
        }
    }
    if (cli->config_path[0] == '\0') {
        snprintf(err, errlen, "--config is required");
        return -1;
    }
    if (!cli->backend_set) {
        snprintf(err, errlen, "--backend posix|fstack is required");
        return -1;
    }
    if (optind != argc) {
        snprintf(err, errlen, "unexpected positional argument: %.200s", argv[optind]);
        return -1;
    }
    return 0;

bad_value:
    snprintf(err, errlen, "invalid value for option near %.200s", optarg ? optarg : "");
    return -1;
}

void config_apply_cli(config_t *cfg, const cli_t *cli) {
    if (cli->scenario_set) snprintf(cfg->scenario, sizeof(cfg->scenario), "%s", cli->scenario);
    if (cli->workload_set) cfg->workload = cli->workload;
    if (cli->mode_set) cfg->mode = cli->mode;
    if (cli->rate_set) cfg->rate_per_s = cli->rate_per_s;
    if (cli->duration_set) cfg->duration_s = cli->duration_s;
    if (cli->max_inflight_set) cfg->max_inflight = cli->max_inflight;
    if (cli->record_connections_set) cfg->record_connections = cli->record_connections;
    if (cli->target_set) snprintf(cfg->target_address, sizeof(cfg->target_address), "%s", cli->target_address);
    if (cli->port_set) cfg->target_port = cli->target_port;
    if (cli->output_set) snprintf(cfg->output_directory, sizeof(cfg->output_directory), "%s", cli->output_directory);
    if (cli->run_id_set) snprintf(cfg->run_id, sizeof(cfg->run_id), "%s", cli->run_id);
    if (cli->fstack_conf_set) snprintf(cfg->fstack_conf, sizeof(cfg->fstack_conf), "%s", cli->fstack_conf);
}

int config_validate(const config_t *cfg, backend_kind_t backend, char *err, size_t errlen) {
    struct in_addr tmp;
    if (inet_pton(AF_INET, cfg->target_address, &tmp) != 1) {
        snprintf(err, errlen, "target.address must be an IPv4 address");
        return -1;
    }
    if (cfg->source_address[0] != '\0' && inet_pton(AF_INET, cfg->source_address, &tmp) != 1) {
        snprintf(err, errlen, "network.source_address must be empty or an IPv4 address");
        return -1;
    }
    if (cfg->target_port == 0 || cfg->rate_per_s <= 0.0 || cfg->duration_s == 0 || cfg->max_inflight == 0) {
        snprintf(err, errlen, "port, rate, duration and max_inflight must be positive");
        return -1;
    }
    if (cfg->payload_size == 0 || cfg->payload_size > 16384) {
        snprintf(err, errlen, "payload.size must be between 1 and 16384 bytes");
        return -1;
    }
    if (cfg->mtu < 576 || cfg->mtu > 9000) {
        snprintf(err, errlen, "network.mtu must be between 576 and 9000");
        return -1;
    }
    if (cfg->record_connections == 0 || cfg->record_connections > cfg->max_inflight) {
        snprintf(err, errlen, "record.connections must be between 1 and max_inflight");
        return -1;
    }
    if (cfg->record_max_pending_releases == 0) {
        snprintf(err, errlen, "record.max_pending_releases must be positive");
        return -1;
    }
    if (cfg->resumption_pool_size == 0 || cfg->resumption_pool_size > cfg->max_inflight) {
        snprintf(err, errlen, "resumption.pool_size must be between 1 and max_inflight");
        return -1;
    }
    if (strcmp(cfg->resumption_policy, "reuse_seed") != 0 && strcmp(cfg->resumption_policy, "fresh_pool") != 0) {
        snprintf(err, errlen, "resumption.session_policy must be reuse_seed or fresh_pool");
        return -1;
    }
    if (strlen(cfg->scenario) != 1 || strchr("ABCDE", cfg->scenario[0]) == NULL) {
        snprintf(err, errlen, "run.scenario must be A, B, C, D or E");
        return -1;
    }
    if (backend == BACKEND_FSTACK && cfg->fstack_conf[0] == '\0') {
        snprintf(err, errlen, "fstack.conf is required for the F-Stack backend");
        return -1;
    }
    if (cfg->verify_peer && cfg->ca_file[0] == '\0') {
        snprintf(err, errlen, "tls.ca_file is required when peer verification is enabled");
        return -1;
    }
    return 0;
}
