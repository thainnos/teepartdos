#define _GNU_SOURCE

#include "tee_tls_d_client.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <tee_client_api.h>

typedef struct {
    TEEC_Context context;
    TEEC_Session session;
    uint32_t last_command;
    TEEC_Result last_result;
    uint32_t last_origin;
} tee_tls_d_internal_t;

static uint64_t diff_us(const struct timespec *start,
                        const struct timespec *end)
{
    int64_t seconds = (int64_t) end->tv_sec - (int64_t) start->tv_sec;
    int64_t nanoseconds =
        (int64_t) end->tv_nsec - (int64_t) start->tv_nsec;

    return (uint64_t) (seconds * 1000000LL + nanoseconds / 1000LL);
}

static void finish_duration(const struct timespec *start,
                            uint64_t *duration_us)
{
    struct timespec end;

    if (duration_us == NULL) {
        return;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    *duration_us = diff_us(start, &end);
}

static tee_tls_d_internal_t *get_internal(tee_tls_d_client_t *client)
{
    if (client == NULL || !client->opened || client->internal == NULL) {
        return NULL;
    }

    return (tee_tls_d_internal_t *) client->internal;
}

static void set_last_error(tee_tls_d_internal_t *internal,
                           uint32_t command,
                           TEEC_Result result,
                           uint32_t origin)
{
    if (internal == NULL) {
        return;
    }

    internal->last_command = command;
    internal->last_result = result;
    internal->last_origin = origin;
}

static uint32_t read_u32_le(const unsigned char *input)
{
    uint32_t value = 0;

    for (size_t i = 0; i < 4; ++i) {
        value |= ((uint32_t) input[i]) << (8U * i);
    }

    return value;
}

static uint64_t read_u64_le(const unsigned char *input)
{
    uint64_t value = 0;

    for (size_t i = 0; i < 8; ++i) {
        value |= ((uint64_t) input[i]) << (8U * i);
    }

    return value;
}

static void write_u32_le(unsigned char *output, uint32_t value)
{
    for (size_t i = 0; i < 4; ++i) {
        output[i] = (unsigned char) ((value >> (8U * i)) & 0xffU);
    }
}

static void write_bytes(unsigned char *output, size_t output_size,
                        const unsigned char *input, size_t input_len)
{
    memset(output, 0, output_size);
    if (input != NULL && input_len <= output_size) {
        memcpy(output, input, input_len);
    }
}

int tee_tls_d_open(tee_tls_d_client_t *client)
{
    TEEC_Result result;
    uint32_t origin = 0;
    TEEC_UUID uuid = TA_TLS_D_BACKEND_UUID;
    tee_tls_d_internal_t *internal;

    if (client == NULL) {
        return -1;
    }

    memset(client, 0, sizeof(*client));

    internal = calloc(1, sizeof(*internal));
    if (internal == NULL) {
        return -1;
    }

    result = TEEC_InitializeContext(NULL, &internal->context);
    if (result != TEEC_SUCCESS) {
        fprintf(stderr,
                "tee_tls_d_open_failed stage=initialize_context "
                "result=0x%08" PRIx32 "\n",
                (uint32_t) result);
        free(internal);
        return -1;
    }

    result = TEEC_OpenSession(&internal->context,
                              &internal->session,
                              &uuid,
                              TEEC_LOGIN_PUBLIC,
                              NULL,
                              NULL,
                              &origin);
    if (result != TEEC_SUCCESS) {
        fprintf(stderr,
                "tee_tls_d_open_failed stage=open_session "
                "result=0x%08" PRIx32 " origin=0x%08" PRIx32 "\n",
                (uint32_t) result,
                origin);
        TEEC_FinalizeContext(&internal->context);
        free(internal);
        return -1;
    }

    set_last_error(internal, UINT32_MAX, TEEC_SUCCESS, 0);
    client->opened = true;
    client->internal = internal;
    return 0;
}

void tee_tls_d_close(tee_tls_d_client_t *client)
{
    tee_tls_d_internal_t *internal = get_internal(client);

    if (internal == NULL) {
        return;
    }

    TEEC_CloseSession(&internal->session);
    TEEC_FinalizeContext(&internal->context);
    memset(internal, 0, sizeof(*internal));
    free(internal);
    memset(client, 0, sizeof(*client));
}

int tee_tls_d_get_caps(tee_tls_d_client_t *client,
                       tee_tls_d_caps_t *caps)
{
    TEEC_Result result;
    uint32_t origin = 0;
    TEEC_Operation operation;
    tee_tls_d_internal_t *internal = get_internal(client);

    if (internal == NULL || caps == NULL) {
        return -1;
    }

    memset(&operation, 0, sizeof(operation));
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
                                            TEEC_VALUE_OUTPUT,
                                            TEEC_NONE,
                                            TEEC_NONE);

    result = TEEC_InvokeCommand(&internal->session,
                                TA_TLS_D_CMD_GET_CAPS,
                                &operation,
                                &origin);
    set_last_error(internal, TA_TLS_D_CMD_GET_CAPS, result, origin);
    if (result != TEEC_SUCCESS) {
        return -1;
    }

    caps->api_version = operation.params[0].value.a;
    caps->capabilities = operation.params[0].value.b;
    caps->max_connections = operation.params[1].value.a;
    return 0;
}

int tee_tls_d_selftest(tee_tls_d_client_t *client,
                       uint64_t *duration_us)
{
    TEEC_Result result;
    uint32_t origin = 0;
    TEEC_Operation operation;
    struct timespec start;
    tee_tls_d_internal_t *internal = get_internal(client);

    if (internal == NULL) {
        return -1;
    }

    memset(&operation, 0, sizeof(operation));
    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    clock_gettime(CLOCK_MONOTONIC, &start);
    result = TEEC_InvokeCommand(&internal->session,
                                TA_TLS_D_CMD_SELFTEST,
                                &operation,
                                &origin);
    finish_duration(&start, duration_us);
    set_last_error(internal, TA_TLS_D_CMD_SELFTEST, result, origin);
    return result == TEEC_SUCCESS ? 0 : -1;
}

int tee_tls_d_connection_open(tee_tls_d_client_t *client,
                              uint32_t *connection_handle,
                              uint64_t *duration_us)
{
    TEEC_Result result;
    uint32_t origin = 0;
    TEEC_Operation operation;
    struct timespec start;
    tee_tls_d_internal_t *internal = get_internal(client);

    if (internal == NULL || connection_handle == NULL) {
        return -1;
    }

    memset(&operation, 0, sizeof(operation));
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
                                            TEEC_NONE,
                                            TEEC_NONE,
                                            TEEC_NONE);

    clock_gettime(CLOCK_MONOTONIC, &start);
    result = TEEC_InvokeCommand(&internal->session,
                                TA_TLS_D_CMD_CONNECTION_OPEN,
                                &operation,
                                &origin);
    finish_duration(&start, duration_us);
    set_last_error(internal, TA_TLS_D_CMD_CONNECTION_OPEN, result, origin);
    if (result != TEEC_SUCCESS) {
        *connection_handle = 0;
        return -1;
    }

    *connection_handle = operation.params[0].value.a;
    return *connection_handle == 0 ? -1 : 0;
}

int tee_tls_d_connection_close(tee_tls_d_client_t *client,
                               uint32_t connection_handle,
                               uint64_t *duration_us)
{
    TEEC_Result result;
    uint32_t origin = 0;
    TEEC_Operation operation;
    struct timespec start;
    tee_tls_d_internal_t *internal = get_internal(client);

    if (internal == NULL || connection_handle == 0) {
        return -1;
    }

    memset(&operation, 0, sizeof(operation));
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                            TEEC_NONE,
                                            TEEC_NONE,
                                            TEEC_NONE);
    operation.params[0].value.a = connection_handle;

    clock_gettime(CLOCK_MONOTONIC, &start);
    result = TEEC_InvokeCommand(&internal->session,
                                TA_TLS_D_CMD_CONNECTION_CLOSE,
                                &operation,
                                &origin);
    finish_duration(&start, duration_us);
    set_last_error(internal, TA_TLS_D_CMD_CONNECTION_CLOSE, result, origin);
    return result == TEEC_SUCCESS ? 0 : -1;
}


int tee_tls_d_transform_import(tee_tls_d_client_t *client,
                               const tee_tls_d_transform_params_t *params,
                               uint32_t *transform_handle,
                               uint64_t *duration_us)
{
    TEEC_Result result;
    uint32_t origin = 0;
    TEEC_Operation operation;
    struct timespec start;
    unsigned char serialized[TEE_TLS_D_IMPORT_SERIALIZED_LEN];
    tee_tls_d_internal_t *internal = get_internal(client);

    if (internal == NULL || params == NULL || transform_handle == NULL ||
        params->connection_handle == 0 ||
        params->key_enc == NULL || params->key_dec == NULL ||
        params->iv_enc == NULL || params->iv_dec == NULL ||
        params->key_enc_len > TEE_TLS_D_MAX_KEY_LEN ||
        params->key_dec_len > TEE_TLS_D_MAX_KEY_LEN ||
        params->iv_enc_len > TEE_TLS_D_MAX_IV_LEN ||
        params->iv_dec_len > TEE_TLS_D_MAX_IV_LEN) {
        return -1;
    }

    memset(serialized, 0, sizeof(serialized));
    write_u32_le(serialized + 0, params->connection_handle);
    write_u32_le(serialized + 4, params->ciphersuite);
    write_u32_le(serialized + 8, params->tls_version);
    write_u32_le(serialized + 12, (uint32_t) params->tag_len);
    write_u32_le(serialized + 16, (uint32_t) params->key_enc_len);
    write_u32_le(serialized + 20, (uint32_t) params->iv_enc_len);
    write_u32_le(serialized + 24, (uint32_t) params->key_dec_len);
    write_u32_le(serialized + 28, (uint32_t) params->iv_dec_len);
    write_bytes(serialized + 32, TEE_TLS_D_MAX_KEY_LEN,
                params->key_enc, params->key_enc_len);
    write_bytes(serialized + 64, TEE_TLS_D_MAX_KEY_LEN,
                params->key_dec, params->key_dec_len);
    write_bytes(serialized + 96, TEE_TLS_D_MAX_IV_LEN,
                params->iv_enc, params->iv_enc_len);
    write_bytes(serialized + 112, TEE_TLS_D_MAX_IV_LEN,
                params->iv_dec, params->iv_dec_len);

    memset(&operation, 0, sizeof(operation));
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                            TEEC_VALUE_OUTPUT,
                                            TEEC_NONE,
                                            TEEC_NONE);
    operation.params[0].tmpref.buffer = serialized;
    operation.params[0].tmpref.size = sizeof(serialized);

    clock_gettime(CLOCK_MONOTONIC, &start);
    result = TEEC_InvokeCommand(&internal->session,
                                TA_TLS_D_CMD_TRANSFORM_IMPORT,
                                &operation,
                                &origin);
    finish_duration(&start, duration_us);
    set_last_error(internal, TA_TLS_D_CMD_TRANSFORM_IMPORT, result, origin);

    memset(serialized, 0, sizeof(serialized));

    if (result != TEEC_SUCCESS) {
        *transform_handle = 0;
        return -1;
    }

    *transform_handle = operation.params[1].value.a;
    return *transform_handle == 0 ? -1 : 0;
}

int tee_tls_d_transform_free(tee_tls_d_client_t *client,
                             uint32_t transform_handle,
                             uint64_t *duration_us)
{
    TEEC_Result result;
    uint32_t origin = 0;
    TEEC_Operation operation;
    struct timespec start;
    tee_tls_d_internal_t *internal = get_internal(client);

    if (internal == NULL || transform_handle == 0) {
        return -1;
    }

    memset(&operation, 0, sizeof(operation));
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                            TEEC_NONE,
                                            TEEC_NONE,
                                            TEEC_NONE);
    operation.params[0].value.a = transform_handle;

    clock_gettime(CLOCK_MONOTONIC, &start);
    result = TEEC_InvokeCommand(&internal->session,
                                TA_TLS_D_CMD_TRANSFORM_FREE,
                                &operation,
                                &origin);
    finish_duration(&start, duration_us);
    set_last_error(internal, TA_TLS_D_CMD_TRANSFORM_FREE, result, origin);
    return result == TEEC_SUCCESS ? 0 : -1;
}

static int invoke_record_operation(tee_tls_d_client_t *client,
                                   uint32_t command,
                                   uint32_t transform_handle,
                                   const unsigned char *aad,
                                   size_t aad_len,
                                   const unsigned char *input,
                                   size_t input_len,
                                   unsigned char *output,
                                   size_t output_size,
                                   size_t *output_len,
                                   uint64_t *duration_us)
{
    TEEC_Result result;
    uint32_t origin = 0;
    TEEC_Operation operation;
    struct timespec start;
    tee_tls_d_internal_t *internal = get_internal(client);
    unsigned char *input_copy = NULL;
    unsigned char *output_tmp = NULL;

    if (internal == NULL || transform_handle == 0 ||
        aad == NULL || aad_len == 0 ||
        input == NULL || output == NULL || output_len == NULL) {
        return -1;
    }

    input_copy = malloc(input_len == 0 ? 1 : input_len);
    output_tmp = malloc(output_size == 0 ? 1 : output_size);
    if (input_copy == NULL || output_tmp == NULL) {
        free(input_copy);
        free(output_tmp);
        return -1;
    }
    if (input_len != 0) {
        memcpy(input_copy, input, input_len);
    }
    memset(output_tmp, 0, output_size);

    memset(&operation, 0, sizeof(operation));
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                            TEEC_MEMREF_TEMP_INPUT,
                                            TEEC_MEMREF_TEMP_INPUT,
                                            TEEC_MEMREF_TEMP_OUTPUT);
    operation.params[0].value.a = transform_handle;
    operation.params[1].tmpref.buffer = (void *) aad;
    operation.params[1].tmpref.size = aad_len;
    operation.params[2].tmpref.buffer = input_copy;
    operation.params[2].tmpref.size = input_len;
    operation.params[3].tmpref.buffer = output_tmp;
    operation.params[3].tmpref.size = output_size;

    clock_gettime(CLOCK_MONOTONIC, &start);
    result = TEEC_InvokeCommand(&internal->session,
                                command,
                                &operation,
                                &origin);
    finish_duration(&start, duration_us);
    set_last_error(internal, command, result, origin);

    if (result == TEEC_SUCCESS) {
        *output_len = operation.params[3].tmpref.size;
        if (*output_len <= output_size) {
            memcpy(output, output_tmp, *output_len);
        } else {
            result = TEEC_ERROR_BAD_PARAMETERS;
        }
    }

    memset(input_copy, 0, input_len);
    memset(output_tmp, 0, output_size);
    free(input_copy);
    free(output_tmp);
    return result == TEEC_SUCCESS ? 0 : -1;
}

int tee_tls_d_record_seal(tee_tls_d_client_t *client,
                          uint32_t transform_handle,
                          const unsigned char *aad,
                          size_t aad_len,
                          const unsigned char *plaintext,
                          size_t plaintext_len,
                          unsigned char *ciphertext,
                          size_t ciphertext_size,
                          size_t *ciphertext_len,
                          uint64_t *duration_us)
{
    return invoke_record_operation(client,
                                   TA_TLS_D_CMD_RECORD_SEAL,
                                   transform_handle,
                                   aad, aad_len,
                                   plaintext, plaintext_len,
                                   ciphertext, ciphertext_size,
                                   ciphertext_len,
                                   duration_us);
}

int tee_tls_d_record_open(tee_tls_d_client_t *client,
                          uint32_t transform_handle,
                          const unsigned char *aad,
                          size_t aad_len,
                          const unsigned char *ciphertext,
                          size_t ciphertext_len,
                          unsigned char *plaintext,
                          size_t plaintext_size,
                          size_t *plaintext_len,
                          uint64_t *duration_us)
{
    return invoke_record_operation(client,
                                   TA_TLS_D_CMD_RECORD_OPEN,
                                   transform_handle,
                                   aad, aad_len,
                                   ciphertext, ciphertext_len,
                                   plaintext, plaintext_size,
                                   plaintext_len,
                                   duration_us);
}


int tee_tls_d_handshake_keys(tee_tls_d_client_t *client,
                             const tee_tls_d_handshake_keys_params_t *params,
                             uint32_t *transform_handle,
                             uint64_t *duration_us)
{
    TEEC_Result result;
    uint32_t origin = 0;
    TEEC_Operation operation;
    struct timespec start;
    unsigned char serialized[TEE_TLS_D_HANDSHAKE_KEYS_SERIALIZED_LEN];
    tee_tls_d_internal_t *internal = get_internal(client);

    if (internal == NULL || params == NULL || transform_handle == NULL ||
        params->connection_handle == 0 || params->transcript == NULL ||
        params->psk_len > TEE_TLS_D_MAX_PSK_LEN ||
        params->shared_secret_len > TEE_TLS_D_MAX_SECRET_LEN ||
        params->peer_public_key_len > TEE_TLS_D_HANDSHAKE_PEER_KEY_MAX_LEN ||
        params->transcript_len > TEE_TLS_D_MAX_TRANSCRIPT_LEN ||
        (params->psk_len != 0 && params->psk == NULL) ||
        (params->shared_secret_len != 0 && params->shared_secret == NULL) ||
        (params->peer_public_key_len != 0 && params->peer_public_key == NULL) ||
        (params->shared_secret_len == 0 && params->peer_public_key_len == 0)) {
        return -1;
    }

    memset(serialized, 0, sizeof(serialized));
    write_u32_le(serialized + 0, params->connection_handle);
    write_u32_le(serialized + 4, params->ciphersuite);
    write_u32_le(serialized + 8, params->tls_version);
    write_u32_le(serialized + 12, (uint32_t) params->psk_len);
    write_u32_le(serialized + 16, (uint32_t) params->psk_type);
    write_u32_le(serialized + 20, (uint32_t) params->shared_secret_len);
    write_u32_le(serialized + 24, (uint32_t) params->peer_public_key_len);
    write_u32_le(serialized + 28, (uint32_t) params->transcript_len);
    write_bytes(serialized + TEE_TLS_D_HANDSHAKE_KEYS_HEADER_LEN,
                TEE_TLS_D_MAX_PSK_LEN,
                params->psk,
                params->psk_len);
    write_bytes(serialized + TEE_TLS_D_HANDSHAKE_KEYS_HEADER_LEN +
                TEE_TLS_D_MAX_PSK_LEN,
                TEE_TLS_D_MAX_SECRET_LEN,
                params->shared_secret,
                params->shared_secret_len);
    write_bytes(serialized + TEE_TLS_D_HANDSHAKE_KEYS_HEADER_LEN +
                TEE_TLS_D_MAX_PSK_LEN +
                TEE_TLS_D_MAX_SECRET_LEN,
                TEE_TLS_D_HANDSHAKE_PEER_KEY_MAX_LEN,
                params->peer_public_key,
                params->peer_public_key_len);
    write_bytes(serialized + TEE_TLS_D_HANDSHAKE_KEYS_HEADER_LEN +
                TEE_TLS_D_MAX_PSK_LEN +
                TEE_TLS_D_MAX_SECRET_LEN +
                TEE_TLS_D_HANDSHAKE_PEER_KEY_MAX_LEN,
                TEE_TLS_D_MAX_TRANSCRIPT_LEN,
                params->transcript,
                params->transcript_len);

    memset(&operation, 0, sizeof(operation));
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                            TEEC_VALUE_OUTPUT,
                                            TEEC_NONE,
                                            TEEC_NONE);
    operation.params[0].tmpref.buffer = serialized;
    operation.params[0].tmpref.size = sizeof(serialized);

    clock_gettime(CLOCK_MONOTONIC, &start);
    result = TEEC_InvokeCommand(&internal->session,
                                TA_TLS_D_CMD_HANDSHAKE_KEYS,
                                &operation,
                                &origin);
    finish_duration(&start, duration_us);
    set_last_error(internal, TA_TLS_D_CMD_HANDSHAKE_KEYS, result, origin);
    memset(serialized, 0, sizeof(serialized));

    if (result != TEEC_SUCCESS) {
        *transform_handle = 0;
        return -1;
    }

    *transform_handle = operation.params[1].value.a;
    return *transform_handle == 0 ? -1 : 0;
}


int tee_tls_d_server_key_share(tee_tls_d_client_t *client,
                               const tee_tls_d_server_key_share_params_t *params,
                               uint64_t *duration_us)
{
    TEEC_Result result;
    uint32_t origin = 0;
    TEEC_Operation operation;
    struct timespec start;
    unsigned char serialized[TEE_TLS_D_SERVER_KEY_SHARE_SERIALIZED_LEN];
    unsigned char output[TEE_TLS_D_MAX_PUBLIC_KEY_LEN];
    tee_tls_d_internal_t *internal = get_internal(client);

    if (internal == NULL || params == NULL ||
        params->connection_handle == 0 || params->public_key == NULL ||
        params->public_key_len == NULL ||
        params->public_key_size < TEE_TLS_D_P256_PUBLIC_KEY_LEN ||
        params->named_group != 0x0017U) {
        return -1;
    }

    memset(serialized, 0, sizeof(serialized));
    memset(output, 0, sizeof(output));
    write_u32_le(serialized + 0, params->connection_handle);
    write_u32_le(serialized + 4, params->named_group);
    write_u32_le(serialized + 8, (uint32_t) params->public_key_size);

    memset(&operation, 0, sizeof(operation));
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                            TEEC_MEMREF_TEMP_OUTPUT,
                                            TEEC_NONE,
                                            TEEC_NONE);
    operation.params[0].tmpref.buffer = serialized;
    operation.params[0].tmpref.size = sizeof(serialized);
    operation.params[1].tmpref.buffer = output;
    operation.params[1].tmpref.size = sizeof(output);

    clock_gettime(CLOCK_MONOTONIC, &start);
    result = TEEC_InvokeCommand(&internal->session,
                                TA_TLS_D_CMD_SERVER_KEY_SHARE,
                                &operation,
                                &origin);
    finish_duration(&start, duration_us);
    set_last_error(internal, TA_TLS_D_CMD_SERVER_KEY_SHARE, result, origin);
    memset(serialized, 0, sizeof(serialized));

    if (result != TEEC_SUCCESS ||
        operation.params[1].tmpref.size > params->public_key_size) {
        memset(output, 0, sizeof(output));
        *params->public_key_len = 0;
        return -1;
    }

    memcpy(params->public_key, output, operation.params[1].tmpref.size);
    *params->public_key_len = operation.params[1].tmpref.size;
    memset(output, 0, sizeof(output));
    return *params->public_key_len == 0 ? -1 : 0;
}

int tee_tls_d_application_keys(tee_tls_d_client_t *client,
                               const tee_tls_d_application_keys_params_t *params,
                               uint32_t *transform_handle,
                               uint64_t *duration_us)
{
    TEEC_Result result;
    uint32_t origin = 0;
    TEEC_Operation operation;
    struct timespec start;
    unsigned char serialized[TEE_TLS_D_APPLICATION_KEYS_SERIALIZED_LEN];
    tee_tls_d_internal_t *internal = get_internal(client);

    if (internal == NULL || params == NULL || transform_handle == NULL ||
        params->connection_handle == 0 || params->transcript == NULL ||
        params->transcript_len > TEE_TLS_D_MAX_TRANSCRIPT_LEN) {
        return -1;
    }

    memset(serialized, 0, sizeof(serialized));
    write_u32_le(serialized + 0, params->connection_handle);
    write_u32_le(serialized + 4, params->ciphersuite);
    write_u32_le(serialized + 8, params->tls_version);
    write_u32_le(serialized + 12, (uint32_t) params->transcript_len);
    write_bytes(serialized + TEE_TLS_D_APPLICATION_KEYS_HEADER_LEN,
                TEE_TLS_D_MAX_TRANSCRIPT_LEN,
                params->transcript,
                params->transcript_len);

    memset(&operation, 0, sizeof(operation));
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                            TEEC_VALUE_OUTPUT,
                                            TEEC_NONE,
                                            TEEC_NONE);
    operation.params[0].tmpref.buffer = serialized;
    operation.params[0].tmpref.size = sizeof(serialized);

    clock_gettime(CLOCK_MONOTONIC, &start);
    result = TEEC_InvokeCommand(&internal->session,
                                TA_TLS_D_CMD_APPLICATION_KEYS,
                                &operation,
                                &origin);
    finish_duration(&start, duration_us);
    set_last_error(internal, TA_TLS_D_CMD_APPLICATION_KEYS, result, origin);
    memset(serialized, 0, sizeof(serialized));

    if (result != TEEC_SUCCESS) {
        *transform_handle = 0;
        return -1;
    }

    *transform_handle = operation.params[1].value.a;
    return *transform_handle == 0 ? -1 : 0;
}

int tee_tls_d_finished(tee_tls_d_client_t *client,
                       const tee_tls_d_finished_params_t *params,
                       uint64_t *duration_us)
{
    TEEC_Result result;
    uint32_t origin = 0;
    TEEC_Operation operation;
    struct timespec start;
    unsigned char serialized[TEE_TLS_D_FINISHED_SERIALIZED_LEN];
    tee_tls_d_internal_t *internal = get_internal(client);

    if (internal == NULL || params == NULL ||
        params->connection_handle == 0 || params->transcript == NULL ||
        params->verify_data == NULL || params->verify_data_len == NULL ||
        params->transcript_len > TEE_TLS_D_MAX_TRANSCRIPT_LEN ||
        params->verify_data_size < TEE_TLS_D_HASH_LEN_SHA256) {
        return -1;
    }

    memset(serialized, 0, sizeof(serialized));
    write_u32_le(serialized + 0, params->connection_handle);
    write_u32_le(serialized + 4, (uint32_t) params->from);
    write_u32_le(serialized + 8, (uint32_t) params->transcript_len);
    write_bytes(serialized + TEE_TLS_D_FINISHED_HEADER_LEN,
                TEE_TLS_D_MAX_TRANSCRIPT_LEN,
                params->transcript,
                params->transcript_len);

    memset(&operation, 0, sizeof(operation));
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                            TEEC_MEMREF_TEMP_OUTPUT,
                                            TEEC_NONE,
                                            TEEC_NONE);
    operation.params[0].tmpref.buffer = serialized;
    operation.params[0].tmpref.size = sizeof(serialized);
    operation.params[1].tmpref.buffer = params->verify_data;
    operation.params[1].tmpref.size = params->verify_data_size;

    clock_gettime(CLOCK_MONOTONIC, &start);
    result = TEEC_InvokeCommand(&internal->session,
                                TA_TLS_D_CMD_FINISHED,
                                &operation,
                                &origin);
    finish_duration(&start, duration_us);
    set_last_error(internal, TA_TLS_D_CMD_FINISHED, result, origin);
    memset(serialized, 0, sizeof(serialized));

    if (result != TEEC_SUCCESS) {
        return -1;
    }

    *params->verify_data_len = operation.params[1].tmpref.size;
    return 0;
}

int tee_tls_d_resumption_master(tee_tls_d_client_t *client,
                                const tee_tls_d_resumption_master_params_t *params,
                                uint64_t *duration_us)
{
    TEEC_Result result;
    uint32_t origin = 0;
    TEEC_Operation operation;
    struct timespec start;
    unsigned char serialized[TEE_TLS_D_RESUMPTION_MASTER_SERIALIZED_LEN];
    tee_tls_d_internal_t *internal = get_internal(client);

    if (internal == NULL || params == NULL ||
        params->connection_handle == 0 || params->transcript == NULL ||
        params->resumption_master == NULL ||
        params->resumption_master_len == NULL ||
        params->transcript_len > TEE_TLS_D_MAX_TRANSCRIPT_LEN ||
        params->resumption_master_size < TEE_TLS_D_HASH_LEN_SHA256) {
        return -1;
    }

    memset(serialized, 0, sizeof(serialized));
    write_u32_le(serialized + 0, params->connection_handle);
    write_u32_le(serialized + 4, params->ciphersuite);
    write_u32_le(serialized + 8, params->tls_version);
    write_u32_le(serialized + 12, (uint32_t) params->transcript_len);
    write_bytes(serialized + TEE_TLS_D_RESUMPTION_MASTER_HEADER_LEN,
                TEE_TLS_D_MAX_TRANSCRIPT_LEN,
                params->transcript,
                params->transcript_len);

    memset(&operation, 0, sizeof(operation));
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                            TEEC_MEMREF_TEMP_OUTPUT,
                                            TEEC_NONE,
                                            TEEC_NONE);
    operation.params[0].tmpref.buffer = serialized;
    operation.params[0].tmpref.size = sizeof(serialized);
    operation.params[1].tmpref.buffer = params->resumption_master;
    operation.params[1].tmpref.size = params->resumption_master_size;

    clock_gettime(CLOCK_MONOTONIC, &start);
    result = TEEC_InvokeCommand(&internal->session,
                                TA_TLS_D_CMD_RESUMPTION_MASTER,
                                &operation,
                                &origin);
    finish_duration(&start, duration_us);
    set_last_error(internal, TA_TLS_D_CMD_RESUMPTION_MASTER, result, origin);
    memset(serialized, 0, sizeof(serialized));

    if (result != TEEC_SUCCESS) {
        return -1;
    }

    *params->resumption_master_len = operation.params[1].tmpref.size;
    return 0;
}

int tee_tls_d_resumption_psk(tee_tls_d_client_t *client,
                             const tee_tls_d_resumption_psk_params_t *params,
                             uint64_t *duration_us)
{
    TEEC_Result result;
    uint32_t origin = 0;
    TEEC_Operation operation;
    struct timespec start;
    unsigned char serialized[TEE_TLS_D_RESUMPTION_PSK_SERIALIZED_LEN];
    tee_tls_d_internal_t *internal = get_internal(client);

    if (internal == NULL || params == NULL ||
        params->connection_handle == 0 || params->ticket_nonce == NULL ||
        params->resumption_psk == NULL || params->resumption_psk_len == NULL ||
        params->ticket_nonce_len > TEE_TLS_D_MAX_TICKET_NONCE_LEN ||
        params->resumption_psk_size < TEE_TLS_D_HASH_LEN_SHA256) {
        return -1;
    }

    memset(serialized, 0, sizeof(serialized));
    write_u32_le(serialized + 0, params->connection_handle);
    write_u32_le(serialized + 4, params->ciphersuite);
    write_u32_le(serialized + 8, params->tls_version);
    write_u32_le(serialized + 12, (uint32_t) params->ticket_nonce_len);
    write_bytes(serialized + TEE_TLS_D_RESUMPTION_PSK_HEADER_LEN,
                TEE_TLS_D_MAX_TICKET_NONCE_LEN,
                params->ticket_nonce,
                params->ticket_nonce_len);

    memset(&operation, 0, sizeof(operation));
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                            TEEC_MEMREF_TEMP_OUTPUT,
                                            TEEC_NONE,
                                            TEEC_NONE);
    operation.params[0].tmpref.buffer = serialized;
    operation.params[0].tmpref.size = sizeof(serialized);
    operation.params[1].tmpref.buffer = params->resumption_psk;
    operation.params[1].tmpref.size = params->resumption_psk_size;

    clock_gettime(CLOCK_MONOTONIC, &start);
    result = TEEC_InvokeCommand(&internal->session,
                                TA_TLS_D_CMD_RESUMPTION_PSK,
                                &operation,
                                &origin);
    finish_duration(&start, duration_us);
    set_last_error(internal, TA_TLS_D_CMD_RESUMPTION_PSK, result, origin);
    memset(serialized, 0, sizeof(serialized));

    if (result != TEEC_SUCCESS) {
        return -1;
    }

    *params->resumption_psk_len = operation.params[1].tmpref.size;
    return 0;
}

int tee_tls_d_get_stats(tee_tls_d_client_t *client,
                        tee_tls_d_stats_t *stats)
{
    TEEC_Result result;
    uint32_t origin = 0;
    TEEC_Operation operation;
    unsigned char serialized[TEE_TLS_D_STATS_SERIALIZED_LEN];
    tee_tls_d_internal_t *internal = get_internal(client);

    if (internal == NULL || stats == NULL) {
        return -1;
    }

    memset(serialized, 0, sizeof(serialized));
    memset(&operation, 0, sizeof(operation));
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                                            TEEC_NONE,
                                            TEEC_NONE,
                                            TEEC_NONE);
    operation.params[0].tmpref.buffer = serialized;
    operation.params[0].tmpref.size = sizeof(serialized);

    result = TEEC_InvokeCommand(&internal->session,
                                TA_TLS_D_CMD_GET_STATS,
                                &operation,
                                &origin);
    set_last_error(internal, TA_TLS_D_CMD_GET_STATS, result, origin);
    if (result != TEEC_SUCCESS ||
        operation.params[0].tmpref.size != sizeof(serialized)) {
        return -1;
    }

    stats->connection_open_calls = read_u64_le(serialized + 0);
    stats->connection_close_calls = read_u64_le(serialized + 8);
    stats->active_connections = read_u64_le(serialized + 16);
    stats->peak_active_connections = read_u64_le(serialized + 24);
    stats->selftest_calls = read_u64_le(serialized + 32);
    stats->failures = read_u64_le(serialized + 40);
    stats->transform_import_calls = read_u64_le(serialized + 48);
    stats->transform_import_success = read_u64_le(serialized + 56);
    stats->transform_import_failure = read_u64_le(serialized + 64);
    stats->transform_free_calls = read_u64_le(serialized + 72);
    stats->transform_free_success = read_u64_le(serialized + 80);
    stats->transform_free_failure = read_u64_le(serialized + 88);
    stats->record_seal_calls = read_u64_le(serialized + 96);
    stats->record_seal_success = read_u64_le(serialized + 104);
    stats->record_seal_failure = read_u64_le(serialized + 112);
    stats->record_open_calls = read_u64_le(serialized + 120);
    stats->record_open_success = read_u64_le(serialized + 128);
    stats->record_open_failure = read_u64_le(serialized + 136);
    stats->handshake_key_calls = read_u64_le(serialized + 144);
    stats->handshake_key_success = read_u64_le(serialized + 152);
    stats->handshake_key_failure = read_u64_le(serialized + 160);
    stats->application_key_calls = read_u64_le(serialized + 168);
    stats->application_key_success = read_u64_le(serialized + 176);
    stats->application_key_failure = read_u64_le(serialized + 184);
    stats->finished_calls = read_u64_le(serialized + 192);
    stats->finished_success = read_u64_le(serialized + 200);
    stats->finished_failure = read_u64_le(serialized + 208);
    stats->server_key_share_calls = read_u64_le(serialized + 216);
    stats->server_key_share_success = read_u64_le(serialized + 224);
    stats->server_key_share_failure = read_u64_le(serialized + 232);
    stats->resumption_master_calls = read_u64_le(serialized + 240);
    stats->resumption_master_success = read_u64_le(serialized + 248);
    stats->resumption_master_failure = read_u64_le(serialized + 256);
    stats->resumption_psk_calls = read_u64_le(serialized + 264);
    stats->resumption_psk_success = read_u64_le(serialized + 272);
    stats->resumption_psk_failure = read_u64_le(serialized + 280);
    return 0;
}

int tee_tls_d_reset_stats(tee_tls_d_client_t *client)
{
    TEEC_Result result;
    uint32_t origin = 0;
    TEEC_Operation operation;
    tee_tls_d_internal_t *internal = get_internal(client);

    if (internal == NULL) {
        return -1;
    }

    memset(&operation, 0, sizeof(operation));
    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    result = TEEC_InvokeCommand(&internal->session,
                                TA_TLS_D_CMD_RESET_STATS,
                                &operation,
                                &origin);
    set_last_error(internal, TA_TLS_D_CMD_RESET_STATS, result, origin);
    return result == TEEC_SUCCESS ? 0 : -1;
}

int tee_tls_d_get_last_error(tee_tls_d_client_t *client,
                             tee_tls_d_error_t *error)
{
    tee_tls_d_internal_t *internal = get_internal(client);

    if (internal == NULL || error == NULL) {
        return -1;
    }

    error->command = internal->last_command;
    error->result = (uint32_t) internal->last_result;
    error->origin = internal->last_origin;
    return 0;
}
