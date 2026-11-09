#include "tls_loadgen.h"

#include <openssl/err.h>
#include <openssl/rand.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static app_t *signal_app;

static void signal_handler(int signo) {
    (void)signo;
    if (signal_app) signal_app->stop_requested = true;
}

static int mkdir_p(const char *path) {
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    if (len == 0) return -1;
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';
    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

static int path_join(char *out, size_t outlen, const char *dir, const char *leaf) {
    if (!out || outlen == 0 || !dir || !leaf) {
        errno = EINVAL;
        return -1;
    }
    size_t dlen = strlen(dir);
    size_t llen = strlen(leaf);
    if (dlen + 1U + llen + 1U > outlen) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(out, dir, dlen);
    out[dlen] = '/';
    memcpy(out + dlen + 1U, leaf, llen + 1U);
    return 0;
}

static void generate_run_id(char *out, size_t outlen) {
    unsigned char bytes[8];
    if (RAND_bytes(bytes, sizeof(bytes)) == 1) {
        snprintf(out, outlen, "%02x%02x%02x%02x%02x%02x%02x%02x",
                 bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]);
    } else {
        snprintf(out, outlen, "%llu-%ld", (unsigned long long)realtime_ns(), (long)getpid());
    }
}

static int write_metadata(app_t *app) {
    FILE *fp = fopen(app->metadata_path, "w");
    if (!fp) return -1;
    fprintf(fp,
        "{\n"
        "  \"run_id\": \"%s\",\n"
        "  \"scenario\": \"%s\",\n"
        "  \"workload\": \"%s\",\n"
        "  \"mode\": \"%s\",\n"
        "  \"backend\": \"%s\",\n"
        "  \"generator_version\": \"%s\",\n"
        "  \"generator_git_commit\": \"%s\",\n"
        "  \"timeline_schema_version\": 1,\n"
        "  \"timeline_file\": \"generator.timeline.json\",\n"
        "  \"stats_wall_time_utc_ns\": true,\n"
        "  \"openssl_compile_version\": \"%s\",\n"
        "  \"openssl_runtime_version\": \"%s\",\n"
        "  \"configured_rate_per_s\": %.9g,\n"
        "  \"configured_duration_s\": %llu,\n"
        "  \"configured_max_inflight\": %u,\n"
        "  \"payload_size\": %zu,\n"
        "  \"record_connections\": %u,\n"
        "  \"record_max_pending_releases\": %u,\n"
        "  \"resumption_policy\": \"%s\",\n"
        "  \"resumption_pool_size\": %u,\n"
        "  \"expected_tls_version\": \"TLSv1.3\",\n"
        "  \"expected_ciphersuite\": \"%s\",\n"
        "  \"expected_group\": \"%s\",\n"
        "  \"expected_signature_algorithm\": \"%s\",\n"
        "  \"certificate_verification_enabled\": %s,\n"
        "  \"network_details_omitted\": true\n"
        "}\n",
        app->cfg.run_id, app->cfg.scenario, workload_name(app->cfg.workload), mode_name(app->cfg.mode),
        app->backend->name, TLSGEN_VERSION, TLSGEN_GIT_COMMIT,
        OPENSSL_VERSION_TEXT, OpenSSL_version(OPENSSL_VERSION),
        app->cfg.rate_per_s, (unsigned long long)app->cfg.duration_s, app->cfg.max_inflight,
        app->cfg.payload_size, app->cfg.record_connections, app->cfg.record_max_pending_releases, app->cfg.resumption_policy,
        app->cfg.resumption_pool_size, app->cfg.ciphersuite, app->cfg.group,
        app->cfg.signature_algorithm, app->cfg.verify_peer ? "true" : "false");
    fclose(fp);
    return 0;
}

static int write_timeline(app_t *app) {
    if (!app || app->timeline_path[0] == '\0') return 0;

    char tmp_path[PATH_MAX];
    int n = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%ld", app->timeline_path, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof(tmp_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    FILE *fp = fopen(tmp_path, "w");
    if (!fp) return -1;
    fprintf(fp,
        "{\n"
        "  \"schema_version\": 1,\n"
        "  \"run_id\": \"%s\",\n"
        "  \"scenario\": \"%s\",\n"
        "  \"workload\": \"%s\",\n"
        "  \"mode\": \"%s\",\n"
        "  \"backend\": \"%s\",\n"
        "  \"generator_version\": \"%s\",\n"
        "  \"generator_git_commit\": \"%s\",\n"
        "  \"clock_realtime\": \"CLOCK_REALTIME\",\n"
        "  \"scheduling_clock\": \"CLOCK_MONOTONIC\",\n"
        "  \"process_started_utc_ns\": %llu,\n"
        "  \"phase_run_started_utc_ns\": %llu,\n"
        "  \"phase_run_end_deadline_utc_ns\": %llu,\n"
        "  \"phase_run_end_observed_utc_ns\": %llu,\n"
        "  \"drain_finished_utc_ns\": %llu,\n"
        "  \"process_finished_utc_ns\": %llu,\n"
        "  \"configured_duration_s\": %llu,\n"
        "  \"run_end_reason\": \"%s\",\n"
        "  \"current_phase\": \"%s\",\n"
        "  \"terminal\": %s\n"
        "}\n",
        app->cfg.run_id, app->cfg.scenario, workload_name(app->cfg.workload),
        mode_name(app->cfg.mode), app->backend ? app->backend->name : "unknown",
        TLSGEN_VERSION, TLSGEN_GIT_COMMIT,
        (unsigned long long)app->process_started_utc_ns,
        (unsigned long long)app->run_started_utc_ns,
        (unsigned long long)app->run_end_deadline_utc_ns,
        (unsigned long long)app->run_end_observed_utc_ns,
        (unsigned long long)app->drain_finished_utc_ns,
        (unsigned long long)app->process_finished_utc_ns,
        (unsigned long long)app->cfg.duration_s,
        app->run_end_reason[0] ? app->run_end_reason : "not-ended",
        phase_name(app->phase),
        (app->phase == PHASE_DONE || app->phase == PHASE_FAILED) ? "true" : "false");

    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0 || fclose(fp) != 0) {
        int saved = errno;
        (void)unlink(tmp_path);
        errno = saved;
        return -1;
    }
    if (rename(tmp_path, app->timeline_path) != 0) {
        int saved = errno;
        (void)unlink(tmp_path);
        errno = saved;
        return -1;
    }
    return 0;
}

static int open_stats(app_t *app) {
    app->stats_csv = fopen(app->stats_path, "w");
    if (!app->stats_csv) return -1;
    fputs("run_id,scenario,workload,mode,backend,wall_time_utc_ns,elapsed_s,phase,offered_total,attempted_total,completed_total,offered_rate,attempted_rate,completed_rate,local_capacity_drop_total,pending_release_current,pending_release_max,release_lag_max_us,session_unavailable_total,tcp_established_total,full_handshake_ok_total,resumed_handshake_ok_total,handshake_fail_total,profile_fail_total,app_ok_total,app_fail_total,payload_fail_total,timeout_fail_total,reconnect_attempted_total,reconnect_ok_total,bytes_tx_total,bytes_rx_total,active_connections,session_pool_size\n", app->stats_csv);
    fflush(app->stats_csv);
    return 0;
}

static uint64_t counter_delta(uint64_t now, uint64_t before) {
    return now >= before ? now - before : 0;
}

static uint32_t active_connections(const app_t *app) {
    uint32_t active = 0;
    for (size_t i = 0; i < app->connection_capacity; ++i) {
        if (app->connections[i].state != CONN_FREE) ++active;
    }
    return active;
}

static void write_stats(app_t *app, uint64_t now) {
    if (!app->stats_csv) return;
    double elapsed = app->run_started_ns && now >= app->run_started_ns ?
        (double)(now - app->run_started_ns) / (double)TLSGEN_NS_PER_S : 0.0;
    double window = app->last_stats_ns && now > app->last_stats_ns ?
        (double)(now - app->last_stats_ns) / (double)TLSGEN_NS_PER_S : 1.0;
    if (window <= 0.0) window = 1.0;
    double offered_rate = (double)counter_delta(app->total.offered, app->previous.offered) / window;
    double attempted_rate = (double)counter_delta(app->total.attempted, app->previous.attempted) / window;
    double completed_rate = (double)counter_delta(app->total.completed, app->previous.completed) / window;

    fprintf(app->stats_csv,
        "%s,%s,%s,%s,%s,%llu,%.6f,%s,"
        "%llu,%llu,%llu,%.3f,%.3f,%.3f,"
        "%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,"
        "%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%u,%zu\n",
        app->cfg.run_id, app->cfg.scenario, workload_name(app->cfg.workload), mode_name(app->cfg.mode), app->backend->name,
        (unsigned long long)realtime_ns(), elapsed, phase_name(app->phase),
        (unsigned long long)app->total.offered,
        (unsigned long long)app->total.attempted,
        (unsigned long long)app->total.completed,
        offered_rate, attempted_rate, completed_rate,
        (unsigned long long)app->total.local_capacity_drop,
        (unsigned long long)app->record_pending_releases,
        (unsigned long long)app->record_pending_releases_max,
        (unsigned long long)(app->release_lag_max_ns / TLSGEN_NS_PER_US),
        (unsigned long long)app->total.session_unavailable,
        (unsigned long long)app->total.tcp_established,
        (unsigned long long)app->total.full_handshake_ok,
        (unsigned long long)app->total.resumed_handshake_ok,
        (unsigned long long)app->total.handshake_fail,
        (unsigned long long)app->total.profile_fail,
        (unsigned long long)app->total.app_ok,
        (unsigned long long)app->total.app_fail,
        (unsigned long long)app->total.payload_fail,
        (unsigned long long)app->total.timeout_fail,
        (unsigned long long)app->total.reconnect_attempted,
        (unsigned long long)app->total.reconnect_ok,
        (unsigned long long)app->total.bytes_tx,
        (unsigned long long)app->total.bytes_rx,
        active_connections(app), app->sessions.count);
    fflush(app->stats_csv);

    if (app->cfg.stdout_progress) {
        fprintf(stdout,
            "stats phase=%s elapsed=%.1f offered=%.1f/s attempted=%.1f/s completed=%.1f/s active=%u sessions=%zu fail_hs=%llu fail_app=%llu local_drop=%llu\n",
            phase_name(app->phase), elapsed, offered_rate, attempted_rate, completed_rate,
            active_connections(app), app->sessions.count,
            (unsigned long long)app->total.handshake_fail,
            (unsigned long long)app->total.app_fail,
            (unsigned long long)app->total.local_capacity_drop);
        fflush(stdout);
    }
    app->previous = app->total;
    app->last_stats_ns = now;
}

static int conn_interest(app_t *app, connection_t *conn, uint32_t events) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = events | EPOLLERR | EPOLLHUP;
    ev.data.ptr = conn;
    int op = conn->epoll_registered ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
    if (app->backend->epoll_ctl(app->epfd, op, conn->fd, &ev) != 0) {
        snprintf(conn->error, sizeof(conn->error), "epoll_ctl failed: %s", strerror(errno));
        conn->failure_stage = FAIL_EPOLL;
        return -1;
    }
    conn->epoll_registered = true;
    conn->epoll_events = ev.events;
    return 0;
}

static void conn_unreg(app_t *app, connection_t *conn) {
    if (conn->epoll_registered && conn->fd >= 0) {
        app->backend->epoll_ctl(app->epfd, EPOLL_CTL_DEL, conn->fd, NULL);
    }
    conn->epoll_registered = false;
}

static void conn_release_tls(connection_t *conn) {
    if (conn->ssl) {
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
    if (conn->bio) {
        BIO_free(conn->bio);
        conn->bio = NULL;
    }
    if (conn->captured_session) {
        SSL_SESSION_free(conn->captured_session);
        conn->captured_session = NULL;
    }
    if (conn->resume_session) {
        SSL_SESSION_free(conn->resume_session);
        conn->resume_session = NULL;
    }
}

static void conn_close_fd(app_t *app, connection_t *conn) {
    conn_unreg(app, conn);
    conn_release_tls(conn);
    if (conn->fd >= 0) {
        app->backend->close(conn->fd);
        conn->fd = -1;
    }
}

static void conn_make_free(app_t *app, connection_t *conn) {
    bool reserved_record = conn->record_connection;
    bool record_ready_counted = conn->record_ready_counted;
    uint64_t retry_after = conn->retry_after_ns;
    uint32_t slot = conn->slot;
    uint8_t *read_buffer = conn->read_buffer;
    conn_close_fd(app, conn);
    memset(conn, 0, sizeof(*conn));
    conn->slot = slot;
    conn->fd = -1;
    conn->state = CONN_FREE;
    conn->read_buffer = read_buffer;
    conn->record_connection = reserved_record;
    conn->record_ready_counted = record_ready_counted;
    conn->retry_after_ns = retry_after;
}

static connection_t *find_free_slot(app_t *app, bool record_slot) {
    for (size_t i = 0; i < app->connection_capacity; ++i) {
        connection_t *conn = &app->connections[i];
        if (conn->state != CONN_FREE) continue;
        if (record_slot && conn->record_connection) return conn;
        if (!record_slot && !conn->record_connection) return conn;
    }
    return NULL;
}

static void best_effort_shutdown(connection_t *conn) {
    if (conn->ssl) {
        ERR_clear_error();
        (void)SSL_shutdown(conn->ssl);
    }
}

static void app_fail(app_t *app, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(app->fatal_error, sizeof(app->fatal_error), fmt, ap);
    va_end(ap);
    if (app->phase == PHASE_RUN && app->run_end_observed_utc_ns == 0) {
        app->run_end_observed_utc_ns = realtime_ns();
        snprintf(app->run_end_reason, sizeof(app->run_end_reason), "%s", "failed");
    }
    app->phase = PHASE_FAILED;
    (void)write_timeline(app);
    fprintf(stderr, "fatal: %s\n", app->fatal_error);
}

static void set_deadline(app_t *app, connection_t *conn, uint64_t timeout_ms) {
    (void)app;
    conn->state_started_ns = monotonic_ns();
    conn->deadline_ns = conn->state_started_ns + timeout_ms * TLSGEN_NS_PER_MS;
}

static void count_failure(app_t *app, connection_t *conn) {
    switch (conn->failure_stage) {
        case FAIL_TLS_HANDSHAKE: ++app->total.handshake_fail; break;
        case FAIL_TLS_PROFILE: ++app->total.profile_fail; break;
        case FAIL_WRITE:
        case FAIL_READ: ++app->total.app_fail; break;
        case FAIL_PAYLOAD: ++app->total.payload_fail; ++app->total.app_fail; break;
        case FAIL_TIMEOUT: ++app->total.timeout_fail; break;
        default: break;
    }
}

static void connection_failed(app_t *app, connection_t *conn) {
    count_failure(app, conn);
    bool fatal_setup = conn->op == OP_PRIME || conn->op == OP_RESUME_PREFLIGHT || conn->op == OP_RECORD_SETUP;
    bool record = conn->record_connection;
    operation_kind_t op = conn->op;
    char detail[TLSGEN_MAX_ERR];
    snprintf(detail, sizeof(detail), "slot=%u op=%d stage=%s error=%.800s", conn->slot, (int)op,
             failure_name(conn->failure_stage), conn->error[0] ? conn->error : "unspecified");

    if (conn->op == OP_PRIME && app->prime_inflight > 0) --app->prime_inflight;
    if (conn->measured && conn->op != OP_RECORD_TRANSACTION) {
        /* offered/attempted already count the failed operation */
    }
    if (record && conn->record_ready_counted && app->record_ready > 0) {
        --app->record_ready;
        conn->record_ready_counted = false;
    }

    if (fatal_setup) {
        conn_close_fd(app, conn);
        app_fail(app, "setup failed: %s", detail);
        return;
    }

    if (record) {
        conn->retry_after_ns = monotonic_ns() + app->cfg.record_reconnect_backoff_ms * TLSGEN_NS_PER_MS;
        conn_make_free(app, conn);
        conn->record_connection = true;
        if (!app->cfg.record_reconnect && app->phase == PHASE_RUN) {
            app_fail(app, "record connection failed and reconnect is disabled: %s", detail);
        }
        return;
    }

    conn->record_connection = false;
    conn_make_free(app, conn);
}

static int set_ssl_interest(app_t *app, connection_t *conn, int ssl_error) {
    if (ssl_error == SSL_ERROR_WANT_READ) return conn_interest(app, conn, EPOLLIN);
    if (ssl_error == SSL_ERROR_WANT_WRITE) return conn_interest(app, conn, EPOLLOUT);
    return -1;
}

static void finish_connection_operation(app_t *app, connection_t *conn);
static void drive_connection(app_t *app, connection_t *conn, uint32_t events);

static int start_tls(app_t *app, connection_t *conn) {
    char err[TLSGEN_MAX_ERR] = {0};
    if (tls_prepare_connection(app, conn, err, sizeof(err)) != 0) {
        conn->failure_stage = FAIL_TLS_OBJECT;
        snprintf(conn->error, sizeof(conn->error), "%s", err);
        return -1;
    }
    conn->state = CONN_TLS_HANDSHAKE;
    set_deadline(app, conn, app->cfg.tls_handshake_timeout_ms);
    drive_connection(app, conn, EPOLLIN | EPOLLOUT);
    return conn->state == CONN_FREE ? -1 : 0;
}

static int start_connection_in_slot(app_t *app, connection_t *conn, operation_kind_t op,
                                    bool measured, SSL_SESSION *session) {
    uint32_t slot = conn->slot;
    bool record_reserved = conn->record_connection;
    bool record_ready_counted = conn->record_ready_counted;
    uint8_t *read_buffer = conn->read_buffer;
    memset(conn, 0, sizeof(*conn));
    conn->slot = slot;
    conn->fd = -1;
    conn->state = CONN_FREE;
    conn->read_buffer = read_buffer;
    conn->record_connection = record_reserved || op == OP_RECORD_SETUP || op == OP_RECORD_RECONNECT;
    conn->record_ready_counted = record_ready_counted;
    conn->op = op;
    conn->measured = measured;
    conn->expected_resumed = op == OP_RESUME || op == OP_RESUME_PREFLIGHT;
    conn->resume_session = session;
    conn->operation_id = ++app->next_operation_id;
    conn->operation_started_ns = monotonic_ns();

    conn->fd = app->backend->socket_create();
    if (conn->fd < 0) {
        conn->failure_stage = FAIL_SOCKET;
        snprintf(conn->error, sizeof(conn->error), "socket failed: %s", strerror(errno));
        connection_failed(app, conn);
        return -1;
    }
    if (app->backend->set_nonblocking(conn->fd) != 0 ||
        app->backend->set_nodelay(conn->fd, app->cfg.tcp_nodelay) != 0) {
        conn->failure_stage = FAIL_SOCKET;
        snprintf(conn->error, sizeof(conn->error), "socket configuration failed: %s", strerror(errno));
        connection_failed(app, conn);
        return -1;
    }
    if (app->backend->bind_source(conn->fd, app->cfg.source_address) != 0) {
        conn->failure_stage = FAIL_BIND;
        snprintf(conn->error, sizeof(conn->error), "source bind failed: %s", strerror(errno));
        connection_failed(app, conn);
        return -1;
    }

    int rc = app->backend->connect_start(conn->fd, &app->target_sockaddr);
    if (rc == 0) {
        ++app->total.tcp_established;
        return start_tls(app, conn);
    }
    if (errno != EINPROGRESS && errno != EALREADY && errno != EWOULDBLOCK) {
        conn->failure_stage = FAIL_CONNECT;
        snprintf(conn->error, sizeof(conn->error), "connect failed: %s", strerror(errno));
        connection_failed(app, conn);
        return -1;
    }

    conn->state = CONN_TCP_CONNECTING;
    set_deadline(app, conn, app->cfg.tcp_connect_timeout_ms);
    if (conn_interest(app, conn, EPOLLOUT) != 0) {
        connection_failed(app, conn);
        return -1;
    }
    return 0;
}

static int start_operation(app_t *app, operation_kind_t op, bool measured) {
    bool record_slot = op == OP_RECORD_SETUP || op == OP_RECORD_RECONNECT;
    connection_t *conn = find_free_slot(app, record_slot);
    if (!conn) return -1;

    SSL_SESSION *session = NULL;
    if (op == OP_RESUME || op == OP_RESUME_PREFLIGHT) {
        if (strcmp(app->cfg.resumption_policy, "fresh_pool") == 0) {
            session = session_pool_pop(&app->sessions);
        } else {
            session = session_pool_duplicate_round_robin(&app->sessions);
        }
        if (!session) return -2;
    }
    return start_connection_in_slot(app, conn, op, measured, session);
}

static void enter_run(app_t *app) {
    uint64_t now = monotonic_ns();
    uint64_t now_utc = realtime_ns();
    app->phase = PHASE_RUN;
    app->phase_started_ns = now;
    app->run_started_ns = now;
    app->run_started_utc_ns = now_utc;
    app->run_end_ns = now + app->cfg.duration_s * TLSGEN_NS_PER_S;
    app->run_end_deadline_utc_ns = now_utc + app->cfg.duration_s * TLSGEN_NS_PER_S;
    app->run_end_observed_utc_ns = 0;
    app->run_end_reason[0] = '\0';
    app->next_release_ns = now;
    app->release_interval_ns = (uint64_t)((double)TLSGEN_NS_PER_S / app->cfg.rate_per_s);
    if (app->release_interval_ns == 0) app->release_interval_ns = 1;
    app->last_stats_ns = now;
    app->previous = app->total;
    fprintf(stdout, "run_start backend=%s scenario=%s workload=%s mode=%s rate=%.3f duration=%llu max_inflight=%u\n",
            app->backend->name, app->cfg.scenario, workload_name(app->cfg.workload), mode_name(app->cfg.mode),
            app->cfg.rate_per_s, (unsigned long long)app->cfg.duration_s, app->cfg.max_inflight);
    (void)write_timeline(app);
}

static void finish_connection_operation(app_t *app, connection_t *conn) {
    switch (conn->op) {
        case OP_PRIME:
            if (!conn->captured_session) {
                conn->failure_stage = FAIL_SESSION;
                snprintf(conn->error, sizeof(conn->error), "no resumable NewSessionTicket captured");
                connection_failed(app, conn);
                return;
            }
            if (session_pool_push(&app->sessions, conn->captured_session) != 0) {
                conn->failure_stage = FAIL_SESSION;
                snprintf(conn->error, sizeof(conn->error), "session pool full");
                connection_failed(app, conn);
                return;
            }
            conn->captured_session = NULL;
            if (app->prime_inflight > 0) --app->prime_inflight;
            best_effort_shutdown(conn);
            conn->record_connection = false;
            conn_make_free(app, conn);
            break;

        case OP_RESUME_PREFLIGHT:
            if (strcmp(app->cfg.resumption_policy, "fresh_pool") == 0) {
                if (!conn->captured_session || session_pool_push(&app->sessions, conn->captured_session) != 0) {
                    conn->failure_stage = FAIL_SESSION;
                    snprintf(conn->error, sizeof(conn->error), "preflight did not replenish fresh session");
                    connection_failed(app, conn);
                    return;
                }
                conn->captured_session = NULL;
            }
            app->preflight_ok = true;
            best_effort_shutdown(conn);
            conn->record_connection = false;
            conn_make_free(app, conn);
            enter_run(app);
            break;

        case OP_FULL:
            ++app->total.completed;
            best_effort_shutdown(conn);
            conn->record_connection = false;
            conn_make_free(app, conn);
            break;

        case OP_RESUME:
            if (strcmp(app->cfg.resumption_policy, "fresh_pool") == 0) {
                if (!conn->captured_session || session_pool_push(&app->sessions, conn->captured_session) != 0) {
                    conn->failure_stage = FAIL_SESSION;
                    snprintf(conn->error, sizeof(conn->error), "resumed connection did not yield a fresh ticket");
                    connection_failed(app, conn);
                    return;
                }
                conn->captured_session = NULL;
            }
            ++app->total.completed;
            best_effort_shutdown(conn);
            conn->record_connection = false;
            conn_make_free(app, conn);
            break;

        case OP_RECORD_SETUP:
            conn->state = CONN_RECORD_IDLE;
            conn->op = OP_NONE;
            conn->deadline_ns = 0;
            if (!conn->record_ready_counted) {
                ++app->record_ready;
                conn->record_ready_counted = true;
            }
            conn_interest(app, conn, EPOLLIN);
            break;

        case OP_RECORD_RECONNECT:
            conn->state = CONN_RECORD_IDLE;
            conn->op = OP_NONE;
            conn->deadline_ns = 0;
            if (!conn->record_ready_counted) {
                ++app->record_ready;
                conn->record_ready_counted = true;
            }
            ++app->total.reconnect_ok;
            conn_interest(app, conn, EPOLLIN);
            break;

        case OP_RECORD_TRANSACTION:
            ++app->total.completed;
            conn->state = CONN_RECORD_IDLE;
            conn->op = OP_NONE;
            conn->deadline_ns = 0;
            conn->pending_record_transaction = false;
            conn->measured = false;
            conn_interest(app, conn, EPOLLIN);
            break;

        case OP_NONE:
            break;
    }
}

static void after_handshake(app_t *app, connection_t *conn) {
    char err[TLSGEN_MAX_ERR] = {0};
    if (tls_validate_profile(app, conn, err, sizeof(err)) != 0) {
        conn->failure_stage = FAIL_TLS_PROFILE;
        snprintf(conn->error, sizeof(conn->error), "%s", err);
        connection_failed(app, conn);
        return;
    }
    if (conn->expected_resumed) ++app->total.resumed_handshake_ok;
    else ++app->total.full_handshake_ok;

    bool need_echo = false;
    bool need_ticket = false;
    switch (conn->op) {
        case OP_FULL: need_echo = app->cfg.full_echo_after_handshake; break;
        case OP_PRIME: need_ticket = true; break;
        case OP_RESUME:
        case OP_RESUME_PREFLIGHT: need_ticket = app->cfg.resumption_wait_for_fresh_ticket || strcmp(app->cfg.resumption_policy, "fresh_pool") == 0; break;
        case OP_RECORD_SETUP:
        case OP_RECORD_RECONNECT: need_echo = true; break;
        default: break;
    }

    if (need_echo) {
        conn->write_offset = 0;
        conn->read_offset = 0;
        conn->state = CONN_APP_WRITE;
        set_deadline(app, conn, app->cfg.io_timeout_ms);
        drive_connection(app, conn, EPOLLOUT);
    } else if (need_ticket && !conn->captured_session) {
        conn->state = CONN_WAIT_TICKET;
        set_deadline(app, conn, app->cfg.io_timeout_ms);
        conn_interest(app, conn, EPOLLIN);
        drive_connection(app, conn, EPOLLIN);
    } else {
        finish_connection_operation(app, conn);
    }
}

static void drive_tls_handshake(app_t *app, connection_t *conn) {
    ERR_clear_error();
    int rc = SSL_connect(conn->ssl);
    if (rc == 1) {
        after_handshake(app, conn);
        return;
    }
    int ssl_error = SSL_get_error(conn->ssl, rc);
    if (set_ssl_interest(app, conn, ssl_error) == 0) return;
    conn->failure_stage = FAIL_TLS_HANDSHAKE;
    openssl_error_string(conn->error, sizeof(conn->error));
    if (conn->error[0] == '\0') snprintf(conn->error, sizeof(conn->error), "SSL_connect failed: SSL_get_error=%d", ssl_error);
    connection_failed(app, conn);
}

static void drive_app_write(app_t *app, connection_t *conn) {
    size_t written = 0;
    ERR_clear_error();
    int rc = SSL_write_ex(conn->ssl, app->payload + conn->write_offset,
                          app->cfg.payload_size - conn->write_offset, &written);
    if (written > 0) {
        conn->write_offset += written;
        app->total.bytes_tx += written;
    }
    if (rc == 1 && conn->write_offset == app->cfg.payload_size) {
        conn->state = CONN_APP_READ;
        set_deadline(app, conn, app->cfg.io_timeout_ms);
        conn_interest(app, conn, EPOLLIN);
        drive_connection(app, conn, EPOLLIN);
        return;
    }
    if (rc == 1) {
        conn_interest(app, conn, EPOLLOUT);
        return;
    }
    int ssl_error = SSL_get_error(conn->ssl, rc);
    if (set_ssl_interest(app, conn, ssl_error) == 0) return;
    conn->failure_stage = FAIL_WRITE;
    openssl_error_string(conn->error, sizeof(conn->error));
    if (conn->error[0] == '\0') snprintf(conn->error, sizeof(conn->error), "SSL_write_ex failed: SSL_get_error=%d", ssl_error);
    connection_failed(app, conn);
}

static void drive_app_read(app_t *app, connection_t *conn) {
    size_t readbytes = 0;
    ERR_clear_error();
    int rc = SSL_read_ex(conn->ssl, conn->read_buffer + conn->read_offset,
                         app->cfg.payload_size - conn->read_offset, &readbytes);
    if (readbytes > 0) {
        conn->read_offset += readbytes;
        app->total.bytes_rx += readbytes;
    }
    if (conn->read_offset == app->cfg.payload_size) {
        if (memcmp(app->payload, conn->read_buffer, app->cfg.payload_size) != 0) {
            conn->failure_stage = FAIL_PAYLOAD;
            snprintf(conn->error, sizeof(conn->error), "echo payload mismatch");
            connection_failed(app, conn);
            return;
        }
        ++app->total.app_ok;
        finish_connection_operation(app, conn);
        return;
    }
    if (rc == 1) {
        conn_interest(app, conn, EPOLLIN);
        return;
    }
    int ssl_error = SSL_get_error(conn->ssl, rc);
    if (set_ssl_interest(app, conn, ssl_error) == 0) return;
    conn->failure_stage = FAIL_READ;
    openssl_error_string(conn->error, sizeof(conn->error));
    if (conn->error[0] == '\0') snprintf(conn->error, sizeof(conn->error), "SSL_read_ex failed: SSL_get_error=%d", ssl_error);
    connection_failed(app, conn);
}

static void drive_wait_ticket(app_t *app, connection_t *conn) {
    if (conn->captured_session) {
        finish_connection_operation(app, conn);
        return;
    }
    unsigned char scratch[1];
    size_t got = 0;
    ERR_clear_error();
    int rc = SSL_read_ex(conn->ssl, scratch, sizeof(scratch), &got);
    if (conn->captured_session) {
        finish_connection_operation(app, conn);
        return;
    }
    if (rc == 1 && got > 0) {
        conn_interest(app, conn, EPOLLIN);
        return;
    }
    int ssl_error = SSL_get_error(conn->ssl, rc);
    if (set_ssl_interest(app, conn, ssl_error) == 0) return;
    conn->failure_stage = FAIL_SESSION;
    openssl_error_string(conn->error, sizeof(conn->error));
    if (conn->error[0] == '\0') snprintf(conn->error, sizeof(conn->error), "failed while waiting for NewSessionTicket: SSL_get_error=%d", ssl_error);
    connection_failed(app, conn);
}

static void drive_tcp_connect(app_t *app, connection_t *conn) {
    int so_error = 0;
    if (app->backend->get_so_error(conn->fd, &so_error) != 0 || so_error != 0) {
        conn->failure_stage = FAIL_CONNECT;
        snprintf(conn->error, sizeof(conn->error), "asynchronous connect failed: %s", strerror(so_error ? so_error : errno));
        connection_failed(app, conn);
        return;
    }
    ++app->total.tcp_established;
    (void)start_tls(app, conn);
}

static void drive_record_idle(app_t *app, connection_t *conn, uint32_t events) {
    if (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
        conn->failure_stage = FAIL_READ;
        snprintf(conn->error, sizeof(conn->error), "record connection closed while idle");
        connection_failed(app, conn);
        return;
    }
    if ((events & EPOLLIN) && SSL_has_pending(conn->ssl)) {
        unsigned char scratch[256];
        size_t got = 0;
        (void)SSL_read_ex(conn->ssl, scratch, sizeof(scratch), &got);
    }
}

static void drive_connection(app_t *app, connection_t *conn, uint32_t events) {
    if (!conn || conn->state == CONN_FREE) return;
    if ((events & (EPOLLERR | EPOLLHUP)) && conn->state != CONN_TCP_CONNECTING && conn->state != CONN_RECORD_IDLE) {
        conn->failure_stage = FAIL_READ;
        snprintf(conn->error, sizeof(conn->error), "socket error/hangup during state %d", (int)conn->state);
        connection_failed(app, conn);
        return;
    }
    switch (conn->state) {
        case CONN_TCP_CONNECTING: drive_tcp_connect(app, conn); break;
        case CONN_TLS_HANDSHAKE: drive_tls_handshake(app, conn); break;
        case CONN_APP_WRITE: drive_app_write(app, conn); break;
        case CONN_APP_READ: drive_app_read(app, conn); break;
        case CONN_WAIT_TICKET: drive_wait_ticket(app, conn); break;
        case CONN_RECORD_IDLE: drive_record_idle(app, conn, events); break;
        case CONN_CLOSING:
        case CONN_FREE:
            break;
    }
}

static void schedule_prime(app_t *app) {
    while (app->sessions.count + app->prime_inflight < app->cfg.resumption_pool_size) {
        connection_t *slot = find_free_slot(app, false);
        if (!slot) break;
        ++app->prime_inflight;
        if (start_connection_in_slot(app, slot, OP_PRIME, false, NULL) != 0 && app->phase == PHASE_FAILED) return;
    }
    if (app->sessions.count >= app->cfg.resumption_pool_size && app->prime_inflight == 0) {
        app->phase = PHASE_PREFLIGHT;
        app->phase_started_ns = monotonic_ns();
    }
}

static void schedule_preflight(app_t *app) {
    if (app->preflight_started) return;
    int rc = start_operation(app, OP_RESUME_PREFLIGHT, false);
    if (rc == -2) {
        app_fail(app, "resumption preflight has no session");
        return;
    }
    if (rc == 0) app->preflight_started = true;
}

static void schedule_record_setup(app_t *app) {
    for (size_t i = 0; i < app->cfg.record_connections; ++i) {
        connection_t *conn = &app->connections[i];
        if (!conn->record_connection) {
            conn->record_connection = true;
            conn->slot = (uint32_t)i;
            conn->fd = -1;
            conn->state = CONN_FREE;
        }
        if (conn->state == CONN_FREE && conn->retry_after_ns == 0) {
            if (start_connection_in_slot(app, conn, OP_RECORD_SETUP, false, NULL) != 0 && app->phase == PHASE_FAILED) return;
        }
    }
    if (app->record_ready == app->cfg.record_connections) enter_run(app);
}

static connection_t *select_record_idle(app_t *app) {
    uint32_t n = app->cfg.record_connections;
    for (uint32_t k = 0; k < n; ++k) {
        uint32_t idx = (uint32_t)((app->record_rr + k) % n);
        connection_t *conn = &app->connections[idx];
        if (conn->state == CONN_RECORD_IDLE) {
            app->record_rr = (uint64_t)(idx + 1) % n;
            return conn;
        }
    }
    return NULL;
}

static void start_record_transaction(app_t *app, connection_t *conn) {
    conn->op = OP_RECORD_TRANSACTION;
    conn->measured = true;
    conn->operation_id = ++app->next_operation_id;
    conn->operation_started_ns = monotonic_ns();
    conn->write_offset = 0;
    conn->read_offset = 0;
    conn->state = CONN_APP_WRITE;
    set_deadline(app, conn, app->cfg.io_timeout_ms);
    ++app->total.attempted;
    drive_connection(app, conn, EPOLLOUT);
}

static void schedule_reconnects(app_t *app, uint64_t now) {
    if (app->cfg.workload != WORKLOAD_RECORD || !app->cfg.record_reconnect) return;
    for (uint32_t i = 0; i < app->cfg.record_connections; ++i) {
        connection_t *conn = &app->connections[i];
        if (conn->record_connection && conn->state == CONN_FREE && conn->retry_after_ns > 0 && now >= conn->retry_after_ns) {
            conn->retry_after_ns = 0;
            ++app->total.reconnect_attempted;
            (void)start_connection_in_slot(app, conn, OP_RECORD_RECONNECT, false, NULL);
        }
    }
}

static void schedule_record_pending(app_t *app) {
    while (app->record_pending_releases > 0) {
        connection_t *conn = select_record_idle(app);
        if (!conn) break;
        start_record_transaction(app, conn);
        --app->record_pending_releases;
    }
}

static void schedule_releases(app_t *app, uint64_t now) {
    uint32_t released = 0;

    /*
     * Network events are processed before this function. First give any older
     * queued arrivals the idle record connections made available by those
     * events. This keeps the queue as a true dispatch backlog rather than a
     * count of all releases observed in the current scheduler callback.
     */
    if (app->cfg.workload == WORKLOAD_RECORD) schedule_record_pending(app);

    if (now >= app->next_release_ns && app->next_release_ns < app->run_end_ns) {
        uint64_t lag = now - app->next_release_ns;
        if (lag > app->release_lag_max_ns) app->release_lag_max_ns = lag;
    }

    while (now >= app->next_release_ns && app->next_release_ns < app->run_end_ns && released < app->cfg.max_release_burst) {
        ++app->total.offered;
        if (app->cfg.workload == WORKLOAD_RECORD) {
            connection_t *conn = select_record_idle(app);
            if (conn) {
                start_record_transaction(app, conn);
            } else if (app->record_pending_releases < app->cfg.record_max_pending_releases) {
                ++app->record_pending_releases;
                if (app->record_pending_releases > app->record_pending_releases_max) {
                    app->record_pending_releases_max = app->record_pending_releases;
                }
            } else {
                ++app->total.local_capacity_drop;
            }
        } else {
            operation_kind_t op = app->cfg.workload == WORKLOAD_FULL ? OP_FULL : OP_RESUME;
            int rc = start_operation(app, op, true);
            if (rc == 0) ++app->total.attempted;
            else if (rc == -2) ++app->total.session_unavailable;
            else ++app->total.local_capacity_drop;
        }
        app->next_release_ns += app->release_interval_ns;
        ++released;
    }
    if (released == app->cfg.max_release_burst && now >= app->next_release_ns) {
        uint64_t skipped = (now - app->next_release_ns) / app->release_interval_ns + 1;
        app->total.offered += skipped;
        app->total.local_capacity_drop += skipped;
        app->next_release_ns += skipped * app->release_interval_ns;
    }
}

static bool any_measured_inflight(const app_t *app) {
    for (size_t i = 0; i < app->connection_capacity; ++i) {
        if (app->connections[i].state != CONN_FREE && app->connections[i].measured) return true;
    }
    return false;
}

static void close_all(app_t *app) {
    for (size_t i = 0; i < app->connection_capacity; ++i) {
        connection_t *conn = &app->connections[i];
        if (conn->state != CONN_FREE || conn->fd >= 0) {
            best_effort_shutdown(conn);
            conn_close_fd(app, conn);
            conn->state = CONN_FREE;
        }
    }
}

static void handle_timeouts(app_t *app, uint64_t now) {
    for (size_t i = 0; i < app->connection_capacity; ++i) {
        connection_t *conn = &app->connections[i];
        if (conn->state == CONN_FREE || conn->state == CONN_RECORD_IDLE || conn->deadline_ns == 0) continue;
        if (now >= conn->deadline_ns) {
            conn->failure_stage = FAIL_TIMEOUT;
            snprintf(conn->error, sizeof(conn->error), "state %d timed out", (int)conn->state);
            connection_failed(app, conn);
            if (app->phase == PHASE_FAILED) return;
        }
    }
}

static void advance_phase(app_t *app, uint64_t now) {
    if (app->stop_requested && app->phase != PHASE_DONE && app->phase != PHASE_FAILED && app->phase != PHASE_DRAIN) {
        if (app->phase == PHASE_RUN && app->run_end_observed_utc_ns == 0) {
            app->run_end_observed_utc_ns = realtime_ns();
            snprintf(app->run_end_reason, sizeof(app->run_end_reason), "%s", "stop-requested");
        }
        app->phase = PHASE_DRAIN;
        app->drain_deadline_ns = now + app->cfg.drain_timeout_ms * TLSGEN_NS_PER_MS;
        (void)write_timeline(app);
    }

    switch (app->phase) {
        case PHASE_PRIME: schedule_prime(app); break;
        case PHASE_PREFLIGHT: schedule_preflight(app); break;
        case PHASE_RECORD_SETUP: schedule_record_setup(app); break;
        case PHASE_RUN:
            schedule_reconnects(app, now);
            schedule_releases(app, now);
            if (now >= app->run_end_ns) {
                if (app->cfg.workload == WORKLOAD_RECORD && app->record_pending_releases > 0) {
                    app->total.local_capacity_drop += app->record_pending_releases;
                    app->record_pending_releases = 0;
                }
                app->run_end_observed_utc_ns = realtime_ns();
                snprintf(app->run_end_reason, sizeof(app->run_end_reason), "%s", "duration-complete");
                app->phase = PHASE_DRAIN;
                app->drain_deadline_ns = now + app->cfg.drain_timeout_ms * TLSGEN_NS_PER_MS;
                (void)write_timeline(app);
            }
            break;
        case PHASE_DRAIN:
            if (!any_measured_inflight(app) || now >= app->drain_deadline_ns) {
                close_all(app);
                app->phase = PHASE_DONE;
                app->drain_finished_utc_ns = realtime_ns();
                write_stats(app, now);
                (void)write_timeline(app);
                fprintf(stdout, "run_end offered=%llu attempted=%llu completed=%llu local_drop=%llu session_unavailable=%llu\n",
                        (unsigned long long)app->total.offered,
                        (unsigned long long)app->total.attempted,
                        (unsigned long long)app->total.completed,
                        (unsigned long long)app->total.local_capacity_drop,
                        (unsigned long long)app->total.session_unavailable);
            }
            break;
        default: break;
    }
}

int app_loop_once(app_t *app, int timeout_ms) {
    struct epoll_event events[TLSGEN_MAX_EVENTS];
    int n = app->backend->epoll_wait(app->epfd, events, TLSGEN_MAX_EVENTS, timeout_ms);
    if (n < 0 && errno != EINTR) {
        app_fail(app, "epoll_wait failed: %s", strerror(errno));
        return -1;
    }
    for (int i = 0; i < n; ++i) {
        connection_t *conn = events[i].data.ptr;
        drive_connection(app, conn, events[i].events);
        if (app->phase == PHASE_FAILED) return -1;
    }

    uint64_t now = monotonic_ns();
    handle_timeouts(app, now);
    if (app->phase == PHASE_FAILED) return -1;
    advance_phase(app, now);

    if (app->last_stats_ns == 0) app->last_stats_ns = now;
    if (now - app->last_stats_ns >= TLSGEN_NS_PER_S && app->phase != PHASE_DONE) write_stats(app, now);
    return app->phase == PHASE_FAILED ? -1 : 0;
}

int app_backend_loop(app_t *app) {
    return app->backend->run(app);
}

void app_request_stop(app_t *app) {
    if (app) app->stop_requested = true;
}

int app_initialize(app_t *app, int argc, char **argv) {
    memset(app, 0, sizeof(*app));
    app->process_started_utc_ns = realtime_ns();
    app->epfd = -1;
    char err[TLSGEN_MAX_ERR] = {0};
    if (cli_parse(argc, argv, &app->cli, err, sizeof(err)) != 0) {
        fprintf(stderr, "error: %s\n", err);
        print_usage(stderr, argv[0]);
        return -1;
    }
    config_defaults(&app->cfg);
    if (config_load(app->cli.config_path, &app->cfg, err, sizeof(err)) != 0) {
        fprintf(stderr, "error: %s\n", err);
        return -1;
    }
    config_apply_cli(&app->cfg, &app->cli);
    if (config_validate(&app->cfg, app->cli.backend, err, sizeof(err)) != 0) {
        fprintf(stderr, "error: %s\n", err);
        return -1;
    }

    app->backend = app->cli.backend == BACKEND_FSTACK ? backend_fstack_ops() : backend_posix_ops();
    if (!app->backend || !app->backend->init || !app->backend->run) {
        fprintf(stderr, "error: selected backend is unavailable\n");
        return -1;
    }

    if (app->cfg.run_id[0] == '\0') generate_run_id(app->cfg.run_id, sizeof(app->cfg.run_id));
    snprintf(app->run_dir, sizeof(app->run_dir), "%s/tls_loadgen_%s_%s_%s_%s",
             app->cfg.output_directory, app->cfg.scenario, workload_name(app->cfg.workload),
             mode_name(app->cfg.mode), app->cfg.run_id);
    if (mkdir_p(app->run_dir) != 0) {
        fprintf(stderr, "error: cannot create output directory %.700s: %s\n", app->run_dir, strerror(errno));
        return -1;
    }
    if (path_join(app->stats_path, sizeof(app->stats_path), app->run_dir, "generator_stats.csv") != 0 ||
        path_join(app->metadata_path, sizeof(app->metadata_path), app->run_dir, "generator.metadata.json") != 0 ||
        path_join(app->timeline_path, sizeof(app->timeline_path), app->run_dir, "generator.timeline.json") != 0) {
        fprintf(stderr, "error: output path is too long\n");
        return -1;
    }

    memset(&app->target_sockaddr, 0, sizeof(app->target_sockaddr));
    app->target_sockaddr.sin_family = AF_INET;
    app->target_sockaddr.sin_port = htons(app->cfg.target_port);
    if (inet_pton(AF_INET, app->cfg.target_address, &app->target_sockaddr.sin_addr) != 1) return -1;

    app->connection_capacity = app->cfg.max_inflight;
    app->connections = calloc(app->connection_capacity, sizeof(*app->connections));
    app->payload = malloc(app->cfg.payload_size);
    if (!app->connections || !app->payload) {
        fprintf(stderr, "error: allocation failed\n");
        return -1;
    }
    memset(app->payload, app->cfg.payload_pattern, app->cfg.payload_size);
    for (size_t i = 0; i < app->connection_capacity; ++i) {
        app->connections[i].slot = (uint32_t)i;
        app->connections[i].fd = -1;
        app->connections[i].state = CONN_FREE;
        app->connections[i].read_buffer = malloc(app->cfg.payload_size);
        if (!app->connections[i].read_buffer) {
            fprintf(stderr, "error: connection buffer allocation failed\n");
            return -1;
        }
    }

    if (session_pool_init(&app->sessions, app->cfg.resumption_pool_size * 2U + 8U) != 0) {
        fprintf(stderr, "error: session pool allocation failed\n");
        return -1;
    }
    app->bio_method = net_bio_method_create();
    if (!app->bio_method) {
        fprintf(stderr, "error: custom OpenSSL BIO creation failed\n");
        return -1;
    }
    app->ssl_ctx = tls_context_create(&app->cfg, err, sizeof(err));
    if (!app->ssl_ctx) {
        fprintf(stderr, "error: TLS context creation failed: %s\n", err);
        return -1;
    }

    if (app->backend->init(app, err, sizeof(err)) != 0) {
        fprintf(stderr, "error: backend initialization failed: %s\n", err);
        return -1;
    }
    app->epfd = app->backend->epoll_create();
    if (app->epfd < 0) {
        fprintf(stderr, "error: backend epoll creation failed: %s\n", strerror(errno));
        return -1;
    }

    if (open_stats(app) != 0 || write_metadata(app) != 0) {
        fprintf(stderr, "error: cannot create run outputs: %s\n", strerror(errno));
        return -1;
    }

    app->phase_started_ns = monotonic_ns();
    if (app->cfg.workload == WORKLOAD_RESUMPTION) {
        app->phase = PHASE_PRIME;
        (void)write_timeline(app);
    } else if (app->cfg.workload == WORKLOAD_RECORD) {
        app->phase = PHASE_RECORD_SETUP;
        (void)write_timeline(app);
    } else {
        enter_run(app);
    }

    signal_app = app;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    return 0;
}

void app_cleanup(app_t *app) {
    if (!app) return;
    close_all(app);
    if (app->stats_csv) {
        fclose(app->stats_csv);
        app->stats_csv = NULL;
    }
    if (app->epfd >= 0 && app->backend && app->backend->close) {
        app->backend->close(app->epfd);
        app->epfd = -1;
    }
    if (app->backend && app->backend->cleanup) app->backend->cleanup(app);

    /* This is the final generator-owned timestamp.  Earlier revisions set it
     * when PHASE_DRAIN completed, before the final statistics/timeline flush
     * and backend cleanup, so the field was not a true process-finalization
     * boundary. */
    if (app->timeline_path[0] != '\0') {
        app->process_finished_utc_ns = realtime_ns();
        (void)write_timeline(app);
    }

    if (app->ssl_ctx) SSL_CTX_free(app->ssl_ctx);
    if (app->bio_method) BIO_meth_free(app->bio_method);
    session_pool_free(&app->sessions);
    if (app->connections) {
        for (size_t i = 0; i < app->connection_capacity; ++i) free(app->connections[i].read_buffer);
    }
    free(app->connections);
    free(app->payload);
    signal_app = NULL;
}
