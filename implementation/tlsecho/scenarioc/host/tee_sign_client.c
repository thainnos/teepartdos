#define _GNU_SOURCE

#include "tee_sign_client.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <tee_client_api.h>

#include "ta_privkey_sign.h"

typedef struct {
    TEEC_Context ctx;
    TEEC_Session sess;
    uint32_t last_command;
    TEEC_Result last_result;
    uint32_t last_origin;
} tee_sign_internal_t;

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

static tee_sign_internal_t *get_internal(tee_sign_client_t *sgn)
{
    if (!sgn || !sgn->opened || !sgn->ctx_opaque) {
        return NULL;
    }
    return (tee_sign_internal_t *)sgn->ctx_opaque;
}

static void set_last_error(tee_sign_internal_t *st,
                           uint32_t command,
                           TEEC_Result result,
                           uint32_t origin)
{
    if (!st) {
        return;
    }
    st->last_command = command;
    st->last_result = result;
    st->last_origin = origin;
}

int tee_sign_open(tee_sign_client_t *sgn)
{
    TEEC_Result res;
    uint32_t origin = 0;
    TEEC_UUID uuid = TA_PRIVKEY_SIGN_UUID;
    tee_sign_internal_t *st;

    if (!sgn) {
        return -1;
    }
    memset(sgn, 0, sizeof(*sgn));

    st = calloc(1, sizeof(*st));
    if (!st) {
        return -1;
    }

    res = TEEC_InitializeContext(NULL, &st->ctx);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr,
                "tee_sign_open_failed stage=initialize_context result=0x%08x\n",
                (unsigned int)res);
        free(st);
        return -1;
    }

    res = TEEC_OpenSession(&st->ctx, &st->sess, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr,
                "tee_sign_open_failed stage=open_session result=0x%08x origin=0x%08x\n",
                (unsigned int)res, (unsigned int)origin);
        TEEC_FinalizeContext(&st->ctx);
        free(st);
        return -1;
    }

    set_last_error(st, UINT32_MAX, TEEC_SUCCESS, 0);
    sgn->opened = true;
    sgn->ctx_opaque = st;
    sgn->sess_opaque = &st->sess;
    return 0;
}

void tee_sign_close(tee_sign_client_t *sgn)
{
    tee_sign_internal_t *st;
    if (!sgn || !sgn->opened || !sgn->ctx_opaque) {
        return;
    }
    st = (tee_sign_internal_t *)sgn->ctx_opaque;
    TEEC_CloseSession(&st->sess);
    TEEC_FinalizeContext(&st->ctx);
    free(st);
    memset(sgn, 0, sizeof(*sgn));
}

int tee_sign_import_p256_key(tee_sign_client_t *sgn,
                             const unsigned char *key_blob,
                             size_t key_blob_len,
                             uint64_t *duration_us)
{
    TEEC_Result res;
    uint32_t origin = 0;
    TEEC_Operation op;
    struct timespec start;
    tee_sign_internal_t *st = get_internal(sgn);

    if (!st || !key_blob || key_blob_len != TEE_SIGN_P256_KEY_BLOB_LEN) {
        return -1;
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_NONE,
                                     TEEC_NONE,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)key_blob;
    op.params[0].tmpref.size = key_blob_len;

    clock_gettime(CLOCK_MONOTONIC, &start);
    res = TEEC_InvokeCommand(&st->sess, TA_SIGN_CMD_IMPORT_P256_KEY, &op, &origin);
    set_duration(&start, duration_us);
    set_last_error(st, TA_SIGN_CMD_IMPORT_P256_KEY, res, origin);
    return res == TEEC_SUCCESS ? 0 : -1;
}

int tee_sign_sign_digest(tee_sign_client_t *sgn,
                         const unsigned char *digest,
                         size_t digest_len,
                         unsigned char *signature,
                         size_t signature_cap,
                         size_t *signature_len,
                         uint64_t *duration_us)
{
    TEEC_Result res;
    uint32_t origin = 0;
    TEEC_Operation op;
    struct timespec start;
    tee_sign_internal_t *st = get_internal(sgn);

    if (!st || !digest || digest_len != TEE_SIGN_SHA256_DIGEST_LEN ||
        !signature || signature_cap < TEE_SIGN_ECDSA_P256_RAW_SIG_LEN || !signature_len) {
        return -1;
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = (void *)digest;
    op.params[0].tmpref.size = digest_len;
    op.params[1].tmpref.buffer = signature;
    op.params[1].tmpref.size = signature_cap;

    clock_gettime(CLOCK_MONOTONIC, &start);
    res = TEEC_InvokeCommand(&st->sess, TA_SIGN_CMD_SIGN_DIGEST, &op, &origin);
    set_duration(&start, duration_us);
    set_last_error(st, TA_SIGN_CMD_SIGN_DIGEST, res, origin);
    if (res != TEEC_SUCCESS) {
        *signature_len = 0;
        return -1;
    }
    *signature_len = op.params[1].tmpref.size;
    return 0;
}

static uint64_t read_u64_le(const unsigned char *p)
{
    uint64_t v = 0;
    for (size_t i = 0; i < 8; ++i) {
        v |= ((uint64_t)p[i]) << (8U * i);
    }
    return v;
}

int tee_sign_get_stats(tee_sign_client_t *sgn, tee_sign_ta_stats_t *stats)
{
    TEEC_Result res;
    uint32_t origin = 0;
    TEEC_Operation op;
    tee_sign_internal_t *st = get_internal(sgn);
    unsigned char out[24];

    if (!st || !stats) {
        return -1;
    }

    memset(&op, 0, sizeof(op));
    memset(out, 0, sizeof(out));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE,
                                     TEEC_NONE,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = out;
    op.params[0].tmpref.size = sizeof(out);

    res = TEEC_InvokeCommand(&st->sess, TA_SIGN_CMD_GET_STATS, &op, &origin);
    set_last_error(st, TA_SIGN_CMD_GET_STATS, res, origin);
    if (res != TEEC_SUCCESS || op.params[0].tmpref.size < sizeof(out)) {
        return -1;
    }

    stats->import_calls = read_u64_le(out + 0);
    stats->sign_calls = read_u64_le(out + 8);
    stats->failures = read_u64_le(out + 16);
    return 0;
}

int tee_sign_reset_stats(tee_sign_client_t *sgn)
{
    TEEC_Result res;
    uint32_t origin = 0;
    TEEC_Operation op;
    tee_sign_internal_t *st = get_internal(sgn);

    if (!st) {
        return -1;
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    res = TEEC_InvokeCommand(&st->sess, TA_SIGN_CMD_RESET_STATS, &op, &origin);
    set_last_error(st, TA_SIGN_CMD_RESET_STATS, res, origin);
    return res == TEEC_SUCCESS ? 0 : -1;
}

int tee_sign_get_last_error(tee_sign_client_t *sgn, tee_sign_error_t *error)
{
    tee_sign_internal_t *st = get_internal(sgn);

    if (!st || !error) {
        return -1;
    }

    error->command = st->last_command;
    error->result = (uint32_t)st->last_result;
    error->origin = st->last_origin;
    return 0;
}
