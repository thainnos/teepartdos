#define _GNU_SOURCE

#include "tee_km_client.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <tee_client_api.h>

#include "ta_key_mgmt.h"

typedef struct {
    TEEC_Context ctx;
    TEEC_Session sess;
    tee_km_last_error_t last_error;
} tee_km_internal_t;

#define TEE_KM_NO_COMMAND UINT32_MAX

static void record_result(tee_km_internal_t *st,
                          uint32_t command_id,
                          TEEC_Result result,
                          uint32_t origin)
{
    if (!st) {
        return;
    }
    st->last_error.command_id = command_id;
    st->last_error.result = (uint32_t)result;
    st->last_error.origin = origin;
}

const char *tee_km_result_name(uint32_t result)
{
    switch (result) {
    case TEEC_SUCCESS: return "TEEC_SUCCESS";
    case TEEC_ERROR_GENERIC: return "TEEC_ERROR_GENERIC";
    case TEEC_ERROR_ACCESS_DENIED: return "TEEC_ERROR_ACCESS_DENIED";
    case TEEC_ERROR_CANCEL: return "TEEC_ERROR_CANCEL";
    case TEEC_ERROR_ACCESS_CONFLICT: return "TEEC_ERROR_ACCESS_CONFLICT";
    case TEEC_ERROR_EXCESS_DATA: return "TEEC_ERROR_EXCESS_DATA";
    case TEEC_ERROR_BAD_FORMAT: return "TEEC_ERROR_BAD_FORMAT";
    case TEEC_ERROR_BAD_PARAMETERS: return "TEEC_ERROR_BAD_PARAMETERS";
    case TEEC_ERROR_BAD_STATE: return "TEEC_ERROR_BAD_STATE";
    case TEEC_ERROR_ITEM_NOT_FOUND: return "TEEC_ERROR_ITEM_NOT_FOUND";
    case TEEC_ERROR_NOT_IMPLEMENTED: return "TEEC_ERROR_NOT_IMPLEMENTED";
    case TEEC_ERROR_NOT_SUPPORTED: return "TEEC_ERROR_NOT_SUPPORTED";
    case TEEC_ERROR_NO_DATA: return "TEEC_ERROR_NO_DATA";
    case TEEC_ERROR_OUT_OF_MEMORY: return "TEEC_ERROR_OUT_OF_MEMORY";
    case TEEC_ERROR_BUSY: return "TEEC_ERROR_BUSY";
    case TEEC_ERROR_COMMUNICATION: return "TEEC_ERROR_COMMUNICATION";
    case TEEC_ERROR_SECURITY: return "TEEC_ERROR_SECURITY";
    case TEEC_ERROR_SHORT_BUFFER: return "TEEC_ERROR_SHORT_BUFFER";
#ifdef TEEC_ERROR_TARGET_DEAD
    case TEEC_ERROR_TARGET_DEAD: return "TEEC_ERROR_TARGET_DEAD";
#endif
#ifdef TEEC_ERROR_MAC_INVALID
    case TEEC_ERROR_MAC_INVALID: return "TEEC_ERROR_MAC_INVALID";
#endif
    default: return "TEEC_ERROR_UNKNOWN";
    }
}

const char *tee_km_origin_name(uint32_t origin)
{
    switch (origin) {
    case TEEC_ORIGIN_API: return "TEEC_ORIGIN_API";
    case TEEC_ORIGIN_COMMS: return "TEEC_ORIGIN_COMMS";
    case TEEC_ORIGIN_TEE: return "TEEC_ORIGIN_TEE";
    case TEEC_ORIGIN_TRUSTED_APP: return "TEEC_ORIGIN_TRUSTED_APP";
    default: return "TEEC_ORIGIN_UNKNOWN";
    }
}

static uint64_t diff_us(const struct timespec *a, const struct timespec *b)
{
    int64_t sec = (int64_t)b->tv_sec - (int64_t)a->tv_sec;
    int64_t nsec = (int64_t)b->tv_nsec - (int64_t)a->tv_nsec;
    return (uint64_t)(sec * 1000000LL + nsec / 1000LL);
}

static void set_duration(struct timespec *start, uint64_t *duration_us)
{
    if (duration_us) {
        struct timespec end;
        clock_gettime(CLOCK_MONOTONIC, &end);
        *duration_us = diff_us(start, &end);
    }
}

static tee_km_internal_t *get_internal(tee_km_client_t *km)
{
    if (!km || !km->opened || !km->ctx_opaque) {
        return NULL;
    }
    return (tee_km_internal_t *)km->ctx_opaque;
}

static const tee_km_internal_t *get_internal_const(const tee_km_client_t *km)
{
    if (!km || !km->opened || !km->ctx_opaque) {
        return NULL;
    }
    return (const tee_km_internal_t *)km->ctx_opaque;
}

int tee_km_get_last_error(const tee_km_client_t *km, tee_km_last_error_t *error)
{
    const tee_km_internal_t *st = get_internal_const(km);
    if (!st || !error) {
        return -1;
    }
    *error = st->last_error;
    return 0;
}

int tee_km_open(tee_km_client_t *km)
{
    TEEC_Result res;
    uint32_t origin = 0;
    TEEC_UUID uuid = TA_KEY_MGMT_UUID;
    tee_km_internal_t *st;

    if (!km) {
        return -1;
    }
    memset(km, 0, sizeof(*km));

    st = calloc(1, sizeof(*st));
    if (!st) {
        return -1;
    }
    st->last_error.command_id = TEE_KM_NO_COMMAND;
    st->last_error.result = TEEC_SUCCESS;
    st->last_error.origin = TEEC_ORIGIN_API;

    res = TEEC_InitializeContext(NULL, &st->ctx);
    if (res != TEEC_SUCCESS) {
        free(st);
        return -1;
    }

    res = TEEC_OpenSession(&st->ctx, &st->sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    record_result(st, TEE_KM_NO_COMMAND, res, origin);
    if (res != TEEC_SUCCESS) {
        TEEC_FinalizeContext(&st->ctx);
        free(st);
        return -1;
    }

    km->opened = true;
    km->ctx_opaque = st;
    km->sess_opaque = &st->sess;
    return 0;
}

void tee_km_close(tee_km_client_t *km)
{
    tee_km_internal_t *st;
    if (!km || !km->opened || !km->ctx_opaque) {
        return;
    }
    st = (tee_km_internal_t *)km->ctx_opaque;
    TEEC_CloseSession(&st->sess);
    TEEC_FinalizeContext(&st->ctx);
    free(st);
    memset(km, 0, sizeof(*km));
}

static int invoke_simple(tee_km_client_t *km, uint32_t cmd, uint64_t *duration_us)
{
    TEEC_Result res;
    uint32_t origin = 0;
    TEEC_Operation op;
    struct timespec start;
    tee_km_internal_t *st = get_internal(km);

    if (!st) {
        return -1;
    }
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    clock_gettime(CLOCK_MONOTONIC, &start);
    res = TEEC_InvokeCommand(&st->sess, cmd, &op, &origin);
    set_duration(&start, duration_us);
    record_result(st, cmd, res, origin);
    return res == TEEC_SUCCESS ? 0 : -1;
}

int tee_km_init_root(tee_km_client_t *km, uint64_t *duration_us)
{
    return invoke_simple(km, TA_KM_CMD_INIT, duration_us);
}

int tee_km_reset_stats(tee_km_client_t *km)
{
    return invoke_simple(km, TA_KM_CMD_RESET_STATS, NULL);
}

static uint64_t read_u64_le(const unsigned char *p)
{
    uint64_t v = 0;
    for (size_t i = 0; i < 8; ++i) {
        v |= ((uint64_t)p[i]) << (8U * i);
    }
    return v;
}

int tee_km_get_stats(tee_km_client_t *km, tee_km_ta_stats_t *stats)
{
    TEEC_Result res;
    uint32_t origin = 0;
    TEEC_Operation op;
    tee_km_internal_t *st = get_internal(km);
    unsigned char out[32];

    if (!st || !stats) {
        return -1;
    }
    memset(&op, 0, sizeof(op));
    memset(out, 0, sizeof(out));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = out;
    op.params[0].tmpref.size = sizeof(out);

    res = TEEC_InvokeCommand(&st->sess, TA_KM_CMD_GET_STATS, &op, &origin);
    record_result(st, TA_KM_CMD_GET_STATS, res, origin);
    if (res != TEEC_SUCCESS || op.params[0].tmpref.size < 32U) {
        return -1;
    }

    stats->derive_calls = read_u64_le(out + 0);
    stats->wrap_calls = read_u64_le(out + 8);
    stats->unwrap_calls = read_u64_le(out + 16);
    stats->failures = read_u64_le(out + 24);
    return 0;
}

int tee_km_derive_session_token(tee_km_client_t *km,
                                const unsigned char *context,
                                size_t context_len,
                                unsigned char token[TEE_KM_TOKEN_LEN],
                                size_t *token_len,
                                uint64_t *duration_us)
{
    TEEC_Result res;
    uint32_t origin = 0;
    TEEC_Operation op;
    struct timespec start;
    tee_km_internal_t *st = get_internal(km);

    if (!st || !context || context_len == 0 || !token) {
        return -1;
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)context;
    op.params[0].tmpref.size = context_len;
    op.params[1].tmpref.buffer = token;
    op.params[1].tmpref.size = TEE_KM_TOKEN_LEN;

    clock_gettime(CLOCK_MONOTONIC, &start);
    res = TEEC_InvokeCommand(&st->sess, TA_KM_CMD_DERIVE_SESSION_TOKEN, &op, &origin);
    set_duration(&start, duration_us);
    record_result(st, TA_KM_CMD_DERIVE_SESSION_TOKEN, res, origin);
    if (res != TEEC_SUCCESS) {
        return -1;
    }
    if (token_len) {
        *token_len = op.params[1].tmpref.size;
    }
    return 0;
}

int tee_km_wrap_session_state(tee_km_client_t *km,
                              const unsigned char *plain,
                              size_t plain_len,
                              unsigned char *blob,
                              size_t blob_cap,
                              size_t *blob_len,
                              uint64_t *duration_us)
{
    TEEC_Result res;
    uint32_t origin = 0;
    TEEC_Operation op;
    struct timespec start;
    tee_km_internal_t *st = get_internal(km);

    if (!st || !plain || plain_len == 0 || !blob || blob_cap == 0 || !blob_len) {
        return -1;
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)plain;
    op.params[0].tmpref.size = plain_len;
    op.params[1].tmpref.buffer = blob;
    op.params[1].tmpref.size = blob_cap;

    clock_gettime(CLOCK_MONOTONIC, &start);
    res = TEEC_InvokeCommand(&st->sess, TA_KM_CMD_WRAP_SESSION_STATE, &op, &origin);
    set_duration(&start, duration_us);
    record_result(st, TA_KM_CMD_WRAP_SESSION_STATE, res, origin);
    if (res != TEEC_SUCCESS) {
        return -1;
    }
    *blob_len = op.params[1].tmpref.size;
    return 0;
}

int tee_km_unwrap_session_state(tee_km_client_t *km,
                                const unsigned char *blob,
                                size_t blob_len,
                                unsigned char *plain,
                                size_t plain_cap,
                                size_t *plain_len,
                                uint64_t *duration_us)
{
    TEEC_Result res;
    uint32_t origin = 0;
    TEEC_Operation op;
    struct timespec start;
    tee_km_internal_t *st = get_internal(km);

    if (!st || !blob || blob_len == 0 || !plain || plain_cap == 0 || !plain_len) {
        return -1;
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)blob;
    op.params[0].tmpref.size = blob_len;
    op.params[1].tmpref.buffer = plain;
    op.params[1].tmpref.size = plain_cap;

    clock_gettime(CLOCK_MONOTONIC, &start);
    res = TEEC_InvokeCommand(&st->sess, TA_KM_CMD_UNWRAP_SESSION_STATE, &op, &origin);
    set_duration(&start, duration_us);
    record_result(st, TA_KM_CMD_UNWRAP_SESSION_STATE, res, origin);
    if (res != TEEC_SUCCESS) {
        return -1;
    }
    *plain_len = op.params[1].tmpref.size;
    return 0;
}
