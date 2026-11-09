#include "tls_loadgen.h"

#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>

uint64_t monotonic_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * TLSGEN_NS_PER_S + (uint64_t)ts.tv_nsec;
}

uint64_t realtime_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * TLSGEN_NS_PER_S + (uint64_t)ts.tv_nsec;
}

const char *workload_name(workload_t workload) {
    switch (workload) {
        case WORKLOAD_FULL: return "full-handshake";
        case WORKLOAD_RESUMPTION: return "resumption";
        case WORKLOAD_RECORD: return "record";
    }
    return "unknown";
}

const char *mode_name(generation_mode_t mode) {
    return mode == MODE_FLOOD ? "flood" : "benign";
}

const char *phase_name(app_phase_t phase) {
    switch (phase) {
        case PHASE_PREPARE: return "prepare";
        case PHASE_PRIME: return "prime";
        case PHASE_PREFLIGHT: return "preflight";
        case PHASE_RECORD_SETUP: return "record-setup";
        case PHASE_RUN: return "run";
        case PHASE_DRAIN: return "drain";
        case PHASE_DONE: return "done";
        case PHASE_FAILED: return "failed";
    }
    return "unknown";
}

const char *failure_name(failure_stage_t stage) {
    switch (stage) {
        case FAIL_NONE: return "none";
        case FAIL_LOCAL_CAPACITY: return "local-capacity";
        case FAIL_SOCKET: return "socket";
        case FAIL_BIND: return "bind";
        case FAIL_CONNECT: return "connect";
        case FAIL_TLS_OBJECT: return "tls-object";
        case FAIL_TLS_HANDSHAKE: return "tls-handshake";
        case FAIL_TLS_PROFILE: return "tls-profile";
        case FAIL_SESSION: return "session";
        case FAIL_WRITE: return "write";
        case FAIL_READ: return "read";
        case FAIL_PAYLOAD: return "payload";
        case FAIL_TIMEOUT: return "timeout";
        case FAIL_EPOLL: return "epoll";
    }
    return "unknown";
}

void openssl_error_string(char *out, size_t outlen) {
    if (!out || outlen == 0) {
        return;
    }
    out[0] = '\0';
    unsigned long code = ERR_get_error();
    if (code != 0) {
        ERR_error_string_n(code, out, outlen);
    }
}

void expand_user_path(const char *input, char *output, size_t output_len) {
    if (!output || output_len == 0) {
        return;
    }
    output[0] = '\0';
    if (!input) {
        return;
    }
    if (input[0] == '~' && (input[1] == '/' || input[1] == '\0')) {
        const char *home = getenv("HOME");
        if (home && home[0] != '\0') {
            snprintf(output, output_len, "%s%s", home, input + 1);
            return;
        }
    }
    snprintf(output, output_len, "%s", input);
}
