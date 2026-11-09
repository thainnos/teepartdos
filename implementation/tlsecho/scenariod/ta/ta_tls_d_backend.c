#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <ta_tls_d_backend.h>

typedef struct {
    bool active;
    uint32_t handle;
    bool has_handshake;
    bool has_application;
    bool has_ecdhe;
    TEE_ObjectHandle ecdhe_keypair;
    uint8_t handshake_secret[TEE_TLS_D_HASH_LEN_SHA256];
    uint8_t master_secret[TEE_TLS_D_HASH_LEN_SHA256];
    uint8_t client_hs_secret[TEE_TLS_D_HASH_LEN_SHA256];
    uint8_t server_hs_secret[TEE_TLS_D_HASH_LEN_SHA256];
    uint8_t client_app_secret[TEE_TLS_D_HASH_LEN_SHA256];
    uint8_t server_app_secret[TEE_TLS_D_HASH_LEN_SHA256];
    bool has_resumption_master;
    uint8_t resumption_master_secret[TEE_TLS_D_HASH_LEN_SHA256];
} connection_slot_t;

typedef struct {
    bool active;
    uint32_t handle;
    uint32_t connection_handle;
    uint8_t key_enc[TEE_TLS_D_MAX_KEY_LEN];
    uint8_t key_dec[TEE_TLS_D_MAX_KEY_LEN];
    uint8_t iv_enc[TEE_TLS_D_MAX_IV_LEN];
    uint8_t iv_dec[TEE_TLS_D_MAX_IV_LEN];
    uint32_t key_enc_len;
    uint32_t key_dec_len;
    uint32_t iv_enc_len;
    uint32_t iv_dec_len;
    uint32_t tag_len;
    uint64_t seq_enc;
    uint64_t seq_dec;
} transform_slot_t;

typedef struct {
    connection_slot_t connections[TEE_TLS_D_MAX_CONNECTIONS];
    transform_slot_t transforms[TEE_TLS_D_MAX_TRANSFORMS];
    uint32_t next_connection_handle;
    uint32_t next_transform_handle;

    uint64_t connection_open_calls;
    uint64_t connection_close_calls;
    uint64_t active_connections;
    uint64_t peak_active_connections;
    uint64_t selftest_calls;
    uint64_t failures;
    uint64_t transform_import_calls;
    uint64_t transform_import_success;
    uint64_t transform_import_failure;
    uint64_t transform_free_calls;
    uint64_t transform_free_success;
    uint64_t transform_free_failure;
    uint64_t record_seal_calls;
    uint64_t record_seal_success;
    uint64_t record_seal_failure;
    uint64_t record_open_calls;
    uint64_t record_open_success;
    uint64_t record_open_failure;
    uint64_t handshake_key_calls;
    uint64_t handshake_key_success;
    uint64_t handshake_key_failure;
    uint64_t application_key_calls;
    uint64_t application_key_success;
    uint64_t application_key_failure;
    uint64_t finished_calls;
    uint64_t finished_success;
    uint64_t finished_failure;
    uint64_t server_key_share_calls;
    uint64_t server_key_share_success;
    uint64_t server_key_share_failure;
    uint64_t resumption_master_calls;
    uint64_t resumption_master_success;
    uint64_t resumption_master_failure;
    uint64_t resumption_psk_calls;
    uint64_t resumption_psk_success;
    uint64_t resumption_psk_failure;
} session_state_t;

static uint32_t read_u32_le(const uint8_t *input)
{
    uint32_t value = 0;

    for (size_t i = 0; i < 4; ++i) {
        value |= ((uint32_t) input[i]) << (8U * i);
    }
    return value;
}

static void write_u64_le(uint8_t *output, uint64_t value)
{
    for (size_t i = 0; i < 8; ++i) {
        output[i] = (uint8_t) ((value >> (8U * i)) & 0xffU);
    }
}

static uint32_t allocate_handle(uint32_t *next_handle)
{
    uint32_t candidate = (*next_handle)++;

    if (candidate == 0) {
        candidate = (*next_handle)++;
    }

    if (*next_handle == 0) {
        *next_handle = 1;
    }

    return candidate;
}

static connection_slot_t *find_connection(session_state_t *state,
                                          uint32_t handle)
{
    if (state == NULL || handle == 0) {
        return NULL;
    }

    for (size_t i = 0; i < TEE_TLS_D_MAX_CONNECTIONS; ++i) {
        if (state->connections[i].active &&
            state->connections[i].handle == handle) {
            return &state->connections[i];
        }
    }
    return NULL;
}

static transform_slot_t *find_transform(session_state_t *state,
                                        uint32_t handle)
{
    if (state == NULL || handle == 0) {
        return NULL;
    }

    for (size_t i = 0; i < TEE_TLS_D_MAX_TRANSFORMS; ++i) {
        if (state->transforms[i].active &&
            state->transforms[i].handle == handle) {
            return &state->transforms[i];
        }
    }
    return NULL;
}

static TEE_Result connection_open_internal(session_state_t *state,
                                           uint32_t *handle,
                                           bool count_stats)
{
    if (state == NULL || handle == NULL) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    for (size_t i = 0; i < TEE_TLS_D_MAX_CONNECTIONS; ++i) {
        if (!state->connections[i].active) {
            uint32_t new_handle = allocate_handle(&state->next_connection_handle);

            state->connections[i].active = true;
            state->connections[i].handle = new_handle;

            if (count_stats) {
                state->connection_open_calls++;
                state->active_connections++;
                if (state->active_connections >
                    state->peak_active_connections) {
                    state->peak_active_connections = state->active_connections;
                }
            }

            *handle = new_handle;
            return TEE_SUCCESS;
        }
    }

    if (count_stats) {
        state->connection_open_calls++;
        state->failures++;
    }
    return TEE_ERROR_OUT_OF_MEMORY;
}

static void free_transform_slot(transform_slot_t *slot)
{
    if (slot == NULL) {
        return;
    }
    TEE_MemFill(slot, 0, sizeof(*slot));
}

static void release_ecdhe_keypair(connection_slot_t *connection)
{
    if (connection == NULL) {
        return;
    }

    if (connection->ecdhe_keypair != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(connection->ecdhe_keypair);
    }
    connection->ecdhe_keypair = TEE_HANDLE_NULL;
    connection->has_ecdhe = false;
}

static TEE_Result connection_close_internal(session_state_t *state,
                                            uint32_t handle,
                                            bool count_stats)
{
    if (state == NULL || handle == 0) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (count_stats) {
        state->connection_close_calls++;
    }

    for (size_t i = 0; i < TEE_TLS_D_MAX_CONNECTIONS; ++i) {
        if (state->connections[i].active &&
            state->connections[i].handle == handle) {
            for (size_t j = 0; j < TEE_TLS_D_MAX_TRANSFORMS; ++j) {
                if (state->transforms[j].active &&
                    state->transforms[j].connection_handle == handle) {
                    free_transform_slot(&state->transforms[j]);
                }
            }

            release_ecdhe_keypair(&state->connections[i]);
            TEE_MemFill(&state->connections[i], 0, sizeof(state->connections[i]));

            if (count_stats && state->active_connections > 0) {
                state->active_connections--;
            }
            return TEE_SUCCESS;
        }
    }

    if (count_stats) {
        state->failures++;
    }
    return TEE_ERROR_ITEM_NOT_FOUND;
}

static void build_tls13_nonce(uint8_t *nonce,
                              const uint8_t *static_iv,
                              uint32_t iv_len,
                              uint64_t sequence)
{
    TEE_MemMove(nonce, static_iv, iv_len);

    for (size_t i = 0; i < 8; ++i) {
        uint8_t seq_byte = (uint8_t) ((sequence >> (8U * (7U - i))) & 0xffU);
        nonce[iv_len - 8U + i] ^= seq_byte;
    }
}


static TEE_Result sha256_digest(const uint8_t *input,
                                size_t input_len,
                                uint8_t output[TEE_TLS_D_HASH_LEN_SHA256])
{
    TEE_Result result;
    TEE_OperationHandle operation = TEE_HANDLE_NULL;
    size_t output_len = TEE_TLS_D_HASH_LEN_SHA256;

    result = TEE_AllocateOperation(&operation,
                                   TEE_ALG_SHA256,
                                   TEE_MODE_DIGEST,
                                   0);
    if (result != TEE_SUCCESS) {
        return result;
    }

    if (input == NULL && input_len == 0) {
        static const uint8_t empty_input[1] = { 0 };
        result = TEE_DigestDoFinal(operation,
                                   (void *) empty_input,
                                   0,
                                   output,
                                   &output_len);
    } else {
        result = TEE_DigestDoFinal(operation,
                                   (void *) input,
                                   input_len,
                                   output,
                                   &output_len);
    }
    TEE_FreeOperation(operation);

    if (result == TEE_SUCCESS && output_len != TEE_TLS_D_HASH_LEN_SHA256) {
        result = TEE_ERROR_BAD_STATE;
    }
    return result;
}

static TEE_Result make_hmac_key(const uint8_t *key,
                                size_t key_len,
                                TEE_ObjectHandle *object)
{
    TEE_Result result;
    TEE_Attribute attr;

    if (key == NULL || key_len == 0 || object == NULL) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    result = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256,
                                         key_len * 8U,
                                         object);
    if (result != TEE_SUCCESS) {
        return result;
    }

    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, key_len);
    result = TEE_PopulateTransientObject(*object, &attr, 1);
    if (result != TEE_SUCCESS) {
        TEE_FreeTransientObject(*object);
        *object = TEE_HANDLE_NULL;
    }
    return result;
}

static TEE_Result hmac_sha256(const uint8_t *key,
                              size_t key_len,
                              const uint8_t *input,
                              size_t input_len,
                              uint8_t output[TEE_TLS_D_HASH_LEN_SHA256])
{
    TEE_Result result;
    TEE_ObjectHandle key_object = TEE_HANDLE_NULL;
    TEE_OperationHandle operation = TEE_HANDLE_NULL;
    size_t output_len = TEE_TLS_D_HASH_LEN_SHA256;

    result = make_hmac_key(key, key_len, &key_object);
    if (result != TEE_SUCCESS) {
        return result;
    }

    result = TEE_AllocateOperation(&operation,
                                   TEE_ALG_HMAC_SHA256,
                                   TEE_MODE_MAC,
                                   key_len * 8U);
    if (result != TEE_SUCCESS) {
        goto cleanup;
    }

    result = TEE_SetOperationKey(operation, key_object);
    if (result != TEE_SUCCESS) {
        goto cleanup;
    }

    TEE_MACInit(operation, NULL, 0);
    result = TEE_MACComputeFinal(operation,
                                 (void *) input,
                                 input_len,
                                 output,
                                 &output_len);
    if (result == TEE_SUCCESS && output_len != TEE_TLS_D_HASH_LEN_SHA256) {
        result = TEE_ERROR_BAD_STATE;
    }

cleanup:
    if (operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(operation);
    }
    if (key_object != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(key_object);
    }
    return result;
}

static TEE_Result hkdf_extract_sha256(const uint8_t *salt,
                                      size_t salt_len,
                                      const uint8_t *ikm,
                                      size_t ikm_len,
                                      uint8_t output[TEE_TLS_D_HASH_LEN_SHA256])
{
    uint8_t zero_salt[TEE_TLS_D_HASH_LEN_SHA256] = { 0 };
    uint8_t zero_ikm[TEE_TLS_D_HASH_LEN_SHA256] = { 0 };

    if (salt == NULL || salt_len == 0) {
        salt = zero_salt;
        salt_len = sizeof(zero_salt);
    }
    if (ikm == NULL || ikm_len == 0) {
        ikm = zero_ikm;
        ikm_len = TEE_TLS_D_HASH_LEN_SHA256;
    }
    return hmac_sha256(salt, salt_len, ikm, ikm_len, output);
}

static TEE_Result hkdf_expand_sha256(const uint8_t secret[TEE_TLS_D_HASH_LEN_SHA256],
                                     const uint8_t *info,
                                     size_t info_len,
                                     uint8_t *output,
                                     size_t output_len)
{
    TEE_Result result;
    uint8_t input[255];
    uint8_t block[TEE_TLS_D_HASH_LEN_SHA256];

    if (secret == NULL || info == NULL || output == NULL ||
        output_len > TEE_TLS_D_HASH_LEN_SHA256 ||
        info_len + 1U > sizeof(input)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_MemMove(input, info, info_len);
    input[info_len] = 0x01U;
    result = hmac_sha256(secret, TEE_TLS_D_HASH_LEN_SHA256,
                         input, info_len + 1U, block);
    if (result == TEE_SUCCESS) {
        TEE_MemMove(output, block, output_len);
    }

    TEE_MemFill(input, 0, sizeof(input));
    TEE_MemFill(block, 0, sizeof(block));
    return result;
}

static TEE_Result hkdf_expand_label_sha256(
    const uint8_t secret[TEE_TLS_D_HASH_LEN_SHA256],
    const char *label,
    const uint8_t *context,
    size_t context_len,
    uint8_t *output,
    size_t output_len)
{
    static const char prefix[] = "tls13 ";
    uint8_t info[2U + 1U + sizeof(prefix) - 1U + 32U + 1U + TEE_TLS_D_MAX_TRANSCRIPT_LEN];
    size_t label_len;
    size_t full_label_len;
    size_t offset = 0;

    if (secret == NULL || label == NULL || output == NULL ||
        output_len > TEE_TLS_D_HASH_LEN_SHA256 ||
        context_len > TEE_TLS_D_MAX_TRANSCRIPT_LEN) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    label_len = strlen(label);
    full_label_len = (sizeof(prefix) - 1U) + label_len;
    if (full_label_len > 255U) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    info[offset++] = (uint8_t) ((output_len >> 8) & 0xffU);
    info[offset++] = (uint8_t) (output_len & 0xffU);
    info[offset++] = (uint8_t) full_label_len;
    TEE_MemMove(info + offset, prefix, sizeof(prefix) - 1U);
    offset += sizeof(prefix) - 1U;
    TEE_MemMove(info + offset, label, label_len);
    offset += label_len;
    info[offset++] = (uint8_t) context_len;
    if (context_len != 0) {
        TEE_MemMove(info + offset, context, context_len);
        offset += context_len;
    }

    return hkdf_expand_sha256(secret, info, offset, output, output_len);
}

static TEE_Result derive_secret_sha256(
    const uint8_t secret[TEE_TLS_D_HASH_LEN_SHA256],
    const char *label,
    const uint8_t transcript_hash[TEE_TLS_D_HASH_LEN_SHA256],
    uint8_t output[TEE_TLS_D_HASH_LEN_SHA256])
{
    return hkdf_expand_label_sha256(secret, label,
                                    transcript_hash,
                                    TEE_TLS_D_HASH_LEN_SHA256,
                                    output,
                                    TEE_TLS_D_HASH_LEN_SHA256);
}

static TEE_Result derive_secret_empty_context_sha256(
    const uint8_t secret[TEE_TLS_D_HASH_LEN_SHA256],
    const char *label,
    uint8_t output[TEE_TLS_D_HASH_LEN_SHA256])
{
    TEE_Result result;
    uint8_t empty_hash[TEE_TLS_D_HASH_LEN_SHA256];

    result = sha256_digest(NULL, 0, empty_hash);
    if (result != TEE_SUCCESS) {
        return result;
    }

    result = derive_secret_sha256(secret, label, empty_hash, output);
    TEE_MemFill(empty_hash, 0, sizeof(empty_hash));
    return result;
}

static TEE_Result evolve_secret_sha256(
    const uint8_t *secret_old,
    const uint8_t *input,
    size_t input_len,
    uint8_t secret_new[TEE_TLS_D_HASH_LEN_SHA256])
{
    TEE_Result result;
    uint8_t tmp_secret[TEE_TLS_D_HASH_LEN_SHA256] = { 0 };

    if (secret_old != NULL) {
        result = derive_secret_empty_context_sha256(secret_old, "derived",
                                                    tmp_secret);
        if (result != TEE_SUCCESS) {
            goto cleanup;
        }
    }

    result = hkdf_extract_sha256(tmp_secret, sizeof(tmp_secret),
                                 input, input_len, secret_new);

cleanup:
    TEE_MemFill(tmp_secret, 0, sizeof(tmp_secret));
    return result;
}

static TEE_Result make_tls13_traffic_key_sha256(
    const uint8_t secret[TEE_TLS_D_HASH_LEN_SHA256],
    uint8_t key[16],
    uint8_t iv[12])
{
    TEE_Result result;

    result = hkdf_expand_label_sha256(secret, "key", NULL, 0, key, 16);
    if (result != TEE_SUCCESS) {
        return result;
    }
    return hkdf_expand_label_sha256(secret, "iv", NULL, 0, iv, 12);
}

static TEE_Result allocate_transform_from_keys(session_state_t *state,
                                               uint32_t connection_handle,
                                               const uint8_t key_enc[16],
                                               const uint8_t iv_enc[12],
                                               const uint8_t key_dec[16],
                                               const uint8_t iv_dec[12],
                                               uint32_t *transform_handle)
{
    if (state == NULL || transform_handle == NULL ||
        find_connection(state, connection_handle) == NULL) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    for (size_t i = 0; i < TEE_TLS_D_MAX_TRANSFORMS; ++i) {
        transform_slot_t *slot = &state->transforms[i];
        if (!slot->active) {
            slot->active = true;
            slot->handle = allocate_handle(&state->next_transform_handle);
            slot->connection_handle = connection_handle;
            slot->tag_len = 16;
            slot->key_enc_len = 16;
            slot->key_dec_len = 16;
            slot->iv_enc_len = 12;
            slot->iv_dec_len = 12;
            TEE_MemMove(slot->key_enc, key_enc, 16);
            TEE_MemMove(slot->key_dec, key_dec, 16);
            TEE_MemMove(slot->iv_enc, iv_enc, 12);
            TEE_MemMove(slot->iv_dec, iv_dec, 12);
            *transform_handle = slot->handle;
            return TEE_SUCCESS;
        }
    }
    return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result make_aes_key(const uint8_t *key,
                               uint32_t key_len,
                               TEE_ObjectHandle *object)
{
    TEE_Result result;
    TEE_Attribute attr;

    if (key == NULL || object == NULL || key_len == 0) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    result = TEE_AllocateTransientObject(TEE_TYPE_AES,
                                         key_len * 8U,
                                         object);
    if (result != TEE_SUCCESS) {
        return result;
    }

    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, key_len);
    result = TEE_PopulateTransientObject(*object, &attr, 1);
    if (result != TEE_SUCCESS) {
        TEE_FreeTransientObject(*object);
        *object = TEE_HANDLE_NULL;
    }
    return result;
}

static TEE_Result aes_gcm_seal(const uint8_t *key,
                               uint32_t key_len,
                               const uint8_t *static_iv,
                               uint32_t iv_len,
                               uint64_t sequence,
                               uint32_t tag_len,
                               const uint8_t *aad,
                               size_t aad_len,
                               const uint8_t *plaintext,
                               size_t plaintext_len,
                               uint8_t *output,
                               size_t *output_len)
{
    TEE_Result result;
    TEE_ObjectHandle key_object = TEE_HANDLE_NULL;
    TEE_OperationHandle operation = TEE_HANDLE_NULL;
    uint8_t nonce[TEE_TLS_D_MAX_IV_LEN];
    uint8_t tag[TEE_TLS_D_MAX_TAG_LEN];
    size_t ciphertext_len = plaintext_len;
    size_t tag_out_len = tag_len;

    if (key == NULL || static_iv == NULL || aad == NULL ||
        plaintext == NULL || output == NULL || output_len == NULL ||
        iv_len > sizeof(nonce) || tag_len > sizeof(tag) ||
        *output_len < plaintext_len + tag_len) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    result = make_aes_key(key, key_len, &key_object);
    if (result != TEE_SUCCESS) {
        return result;
    }

    result = TEE_AllocateOperation(&operation,
                                   TEE_ALG_AES_GCM,
                                   TEE_MODE_ENCRYPT,
                                   key_len * 8U);
    if (result != TEE_SUCCESS) {
        goto cleanup;
    }

    result = TEE_SetOperationKey(operation, key_object);
    if (result != TEE_SUCCESS) {
        goto cleanup;
    }

    build_tls13_nonce(nonce, static_iv, iv_len, sequence);
    result = TEE_AEInit(operation,
                        nonce,
                        iv_len,
                        tag_len * 8U,
                        aad_len,
                        plaintext_len);
    if (result != TEE_SUCCESS) {
        goto cleanup;
    }

    TEE_AEUpdateAAD(operation, aad, aad_len);
    result = TEE_AEEncryptFinal(operation,
                                plaintext,
                                plaintext_len,
                                output,
                                &ciphertext_len,
                                tag,
                                &tag_out_len);
    if (result == TEE_SUCCESS) {
        if (tag_out_len != tag_len) {
            result = TEE_ERROR_BAD_STATE;
        } else {
            TEE_MemMove(output + ciphertext_len, tag, tag_len);
            *output_len = ciphertext_len + tag_len;
        }
    }

cleanup:
    TEE_MemFill(nonce, 0, sizeof(nonce));
    TEE_MemFill(tag, 0, sizeof(tag));
    if (operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(operation);
    }
    if (key_object != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(key_object);
    }
    return result;
}

static TEE_Result aes_gcm_open(const uint8_t *key,
                               uint32_t key_len,
                               const uint8_t *static_iv,
                               uint32_t iv_len,
                               uint64_t sequence,
                               uint32_t tag_len,
                               const uint8_t *aad,
                               size_t aad_len,
                               const uint8_t *ciphertext,
                               size_t ciphertext_len,
                               uint8_t *output,
                               size_t *output_len)
{
    TEE_Result result;
    TEE_ObjectHandle key_object = TEE_HANDLE_NULL;
    TEE_OperationHandle operation = TEE_HANDLE_NULL;
    uint8_t nonce[TEE_TLS_D_MAX_IV_LEN];
    const uint8_t *tag;
    size_t plaintext_len;

    if (key == NULL || static_iv == NULL || aad == NULL ||
        ciphertext == NULL || output == NULL || output_len == NULL ||
        iv_len > sizeof(nonce) || tag_len > TEE_TLS_D_MAX_TAG_LEN ||
        ciphertext_len < tag_len) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    plaintext_len = ciphertext_len - tag_len;
    tag = ciphertext + plaintext_len;
    if (*output_len < plaintext_len) {
        return TEE_ERROR_SHORT_BUFFER;
    }
    *output_len = plaintext_len;

    result = make_aes_key(key, key_len, &key_object);
    if (result != TEE_SUCCESS) {
        return result;
    }

    result = TEE_AllocateOperation(&operation,
                                   TEE_ALG_AES_GCM,
                                   TEE_MODE_DECRYPT,
                                   key_len * 8U);
    if (result != TEE_SUCCESS) {
        goto cleanup;
    }

    result = TEE_SetOperationKey(operation, key_object);
    if (result != TEE_SUCCESS) {
        goto cleanup;
    }

    build_tls13_nonce(nonce, static_iv, iv_len, sequence);
    result = TEE_AEInit(operation,
                        nonce,
                        iv_len,
                        tag_len * 8U,
                        aad_len,
                        plaintext_len);
    if (result != TEE_SUCCESS) {
        goto cleanup;
    }

    TEE_AEUpdateAAD(operation, aad, aad_len);
    result = TEE_AEDecryptFinal(operation,
                                ciphertext,
                                plaintext_len,
                                output,
                                output_len,
                                (void *) tag,
                                tag_len);

cleanup:
    TEE_MemFill(nonce, 0, sizeof(nonce));
    if (operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(operation);
    }
    if (key_object != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(key_object);
    }
    return result;
}

static bool tee_tls_d_profile_supported(uint32_t ciphersuite,
                                        uint32_t tls_version)
{
    return ciphersuite == TEE_TLS_D_PROFILE_CIPHERSUITE &&
           tls_version == TEE_TLS_D_PROFILE_TLS_VERSION;
}

static TEE_Result command_get_caps(uint32_t param_types,
                                   TEE_Param params[4])
{
    const uint32_t expected =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
                        TEE_PARAM_TYPE_VALUE_OUTPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);

    if (param_types != expected) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    params[0].value.a = TEE_TLS_D_API_VERSION;
    params[0].value.b =
        TEE_TLS_D_CAP_CONNECTION_LIFECYCLE |
        TEE_TLS_D_CAP_TRANSFORM_LIFECYCLE |
        TEE_TLS_D_CAP_RECORD_AEAD |
        TEE_TLS_D_CAP_KEY_SCHEDULE |
        TEE_TLS_D_CAP_FINISHED |
        TEE_TLS_D_CAP_ECDHE |
	TEE_TLS_D_CAP_RESUMPTION;
    params[1].value.a = TEE_TLS_D_MAX_CONNECTIONS;
    params[1].value.b = TEE_TLS_D_MAX_TRANSFORMS;
    return TEE_SUCCESS;
}

static TEE_Result command_selftest(session_state_t *state,
                                   uint32_t param_types,
                                   TEE_Param params[4])
{
    const uint32_t expected =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);
    TEE_Result result;
    uint32_t handle = 0;

    (void) params;

    if (state == NULL || param_types != expected) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    state->selftest_calls++;

    result = connection_open_internal(state, &handle, false);
    if (result != TEE_SUCCESS) {
        state->failures++;
        return result;
    }

    result = connection_close_internal(state, handle, false);
    if (result != TEE_SUCCESS) {
        state->failures++;
        return result;
    }

    {
        static const uint8_t key[TEE_TLS_D_HASH_LEN_SHA256] = { 0 };
        static const uint8_t msg[1] = { 0 };
        uint8_t digest[TEE_TLS_D_HASH_LEN_SHA256];
        uint8_t mac[TEE_TLS_D_HASH_LEN_SHA256];

        result = sha256_digest(msg, 0, digest);
        if (result != TEE_SUCCESS) {
            state->failures++;
            return result;
        }
        result = hmac_sha256(key, sizeof(key), msg, 0, mac);
        if (result != TEE_SUCCESS) {
            state->failures++;
            return result;
        }
        TEE_MemFill(digest, 0, sizeof(digest));
        TEE_MemFill(mac, 0, sizeof(mac));
    }

    return TEE_SUCCESS;
}

static TEE_Result command_connection_open(session_state_t *state,
                                          uint32_t param_types,
                                          TEE_Param params[4])
{
    const uint32_t expected =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);
    TEE_Result result;
    uint32_t handle = 0;

    if (state == NULL || param_types != expected) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    result = connection_open_internal(state, &handle, true);
    if (result == TEE_SUCCESS) {
        params[0].value.a = handle;
        params[0].value.b = 0;
    }
    return result;
}

static TEE_Result command_connection_close(session_state_t *state,
                                           uint32_t param_types,
                                           TEE_Param params[4])
{
    const uint32_t expected =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);

    if (state == NULL || param_types != expected) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return connection_close_internal(state, params[0].value.a, true);
}

static TEE_Result command_transform_import(session_state_t *state,
                                           uint32_t param_types,
                                           TEE_Param params[4])
{
    const uint32_t expected =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_VALUE_OUTPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);
    const uint8_t *input;
    uint32_t connection_handle;
    uint32_t tag_len;
    uint32_t key_enc_len;
    uint32_t iv_enc_len;
    uint32_t key_dec_len;
    uint32_t iv_dec_len;

    if (state == NULL || param_types != expected ||
        params[0].memref.buffer == NULL ||
        params[0].memref.size != TEE_TLS_D_IMPORT_SERIALIZED_LEN) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    state->transform_import_calls++;
    input = (const uint8_t *) params[0].memref.buffer;
    connection_handle = read_u32_le(input + 0);
    tag_len = read_u32_le(input + 12);
    key_enc_len = read_u32_le(input + 16);
    iv_enc_len = read_u32_le(input + 20);
    key_dec_len = read_u32_le(input + 24);
    iv_dec_len = read_u32_le(input + 28);

    if (find_connection(state, connection_handle) == NULL ||
        tag_len < TEE_TLS_D_MIN_TAG_LEN || tag_len > TEE_TLS_D_MAX_TAG_LEN ||
        key_enc_len == 0 || key_enc_len > TEE_TLS_D_MAX_KEY_LEN ||
        key_dec_len == 0 || key_dec_len > TEE_TLS_D_MAX_KEY_LEN ||
        iv_enc_len < 8 || iv_enc_len > TEE_TLS_D_MAX_IV_LEN ||
        iv_dec_len < 8 || iv_dec_len > TEE_TLS_D_MAX_IV_LEN) {
        state->transform_import_failure++;
        state->failures++;
        return TEE_ERROR_BAD_PARAMETERS;
    }

    for (size_t i = 0; i < TEE_TLS_D_MAX_TRANSFORMS; ++i) {
        transform_slot_t *slot = &state->transforms[i];
        if (!slot->active) {
            slot->active = true;
            slot->handle = allocate_handle(&state->next_transform_handle);
            slot->connection_handle = connection_handle;
            slot->tag_len = tag_len;
            slot->key_enc_len = key_enc_len;
            slot->key_dec_len = key_dec_len;
            slot->iv_enc_len = iv_enc_len;
            slot->iv_dec_len = iv_dec_len;
            TEE_MemMove(slot->key_enc, input + 32, key_enc_len);
            TEE_MemMove(slot->key_dec, input + 64, key_dec_len);
            TEE_MemMove(slot->iv_enc, input + 96, iv_enc_len);
            TEE_MemMove(slot->iv_dec, input + 112, iv_dec_len);
            params[1].value.a = slot->handle;
            params[1].value.b = 0;
            state->transform_import_success++;
            return TEE_SUCCESS;
        }
    }

    state->transform_import_failure++;
    state->failures++;
    return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result command_transform_free(session_state_t *state,
                                         uint32_t param_types,
                                         TEE_Param params[4])
{
    const uint32_t expected =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);
    transform_slot_t *slot;

    if (state == NULL || param_types != expected) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    state->transform_free_calls++;
    slot = find_transform(state, params[0].value.a);
    if (slot == NULL) {
        state->transform_free_failure++;
        state->failures++;
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    free_transform_slot(slot);
    state->transform_free_success++;
    return TEE_SUCCESS;
}

static TEE_Result command_record_seal(session_state_t *state,
                                      uint32_t param_types,
                                      TEE_Param params[4])
{
    const uint32_t expected =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                        TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_MEMREF_OUTPUT);
    transform_slot_t *slot;
    TEE_Result result;
    size_t output_len;

    if (state == NULL || param_types != expected ||
        params[1].memref.buffer == NULL ||
        params[2].memref.buffer == NULL ||
        params[3].memref.buffer == NULL) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    state->record_seal_calls++;
    slot = find_transform(state, params[0].value.a);
    if (slot == NULL) {
        state->record_seal_failure++;
        state->failures++;
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    output_len = params[3].memref.size;
    result = aes_gcm_seal(slot->key_enc,
                          slot->key_enc_len,
                          slot->iv_enc,
                          slot->iv_enc_len,
                          slot->seq_enc,
                          slot->tag_len,
                          (const uint8_t *) params[1].memref.buffer,
                          params[1].memref.size,
                          (const uint8_t *) params[2].memref.buffer,
                          params[2].memref.size,
                          (uint8_t *) params[3].memref.buffer,
                          &output_len);
    if (result == TEE_SUCCESS) {
        params[3].memref.size = output_len;
        slot->seq_enc++;
        state->record_seal_success++;
    } else {
        state->record_seal_failure++;
        state->failures++;
    }
    return result;
}

static TEE_Result command_record_open(session_state_t *state,
                                      uint32_t param_types,
                                      TEE_Param params[4])
{
    const uint32_t expected =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                        TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_MEMREF_OUTPUT);
    transform_slot_t *slot;
    TEE_Result result;
    size_t output_len;

    if (state == NULL || param_types != expected ||
        params[1].memref.buffer == NULL ||
        params[2].memref.buffer == NULL ||
        params[3].memref.buffer == NULL) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    state->record_open_calls++;
    slot = find_transform(state, params[0].value.a);
    if (slot == NULL) {
        state->record_open_failure++;
        state->failures++;
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    output_len = params[3].memref.size;
    result = aes_gcm_open(slot->key_dec,
                          slot->key_dec_len,
                          slot->iv_dec,
                          slot->iv_dec_len,
                          slot->seq_dec,
                          slot->tag_len,
                          (const uint8_t *) params[1].memref.buffer,
                          params[1].memref.size,
                          (const uint8_t *) params[2].memref.buffer,
                          params[2].memref.size,
                          (uint8_t *) params[3].memref.buffer,
                          &output_len);
    if (result == TEE_SUCCESS) {
        params[3].memref.size = output_len;
        slot->seq_dec++;
        state->record_open_success++;
    } else {
        state->record_open_failure++;
        state->failures++;
    }
    return result;
}



static TEE_Result parse_p256_public_key(const uint8_t *public_key,
                                        uint32_t public_key_len,
                                        const uint8_t **x,
                                        const uint8_t **y)
{
    if (public_key == NULL || x == NULL || y == NULL ||
        public_key_len != TEE_TLS_D_P256_PUBLIC_KEY_LEN ||
        public_key[0] != 0x04U) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    *x = public_key + 1;
    *y = public_key + 1 + TEE_TLS_D_P256_PRIVATE_KEY_LEN;
    return TEE_SUCCESS;
}

static TEE_Result command_server_key_share(session_state_t *state,
                                           uint32_t param_types,
                                           TEE_Param params[4])
{
    const uint32_t expected =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);
    const uint8_t *input;
    uint8_t *output;
    connection_slot_t *connection;
    uint32_t connection_handle;
    uint32_t named_group;
    uint32_t public_key_size;
    TEE_Result result;
    TEE_Attribute curve_attr;
    uint8_t x[TEE_TLS_D_P256_PRIVATE_KEY_LEN];
    uint8_t y[TEE_TLS_D_P256_PRIVATE_KEY_LEN];
    size_t x_len = sizeof(x);
    size_t y_len = sizeof(y);

    if (state == NULL || param_types != expected ||
        params[0].memref.buffer == NULL || params[1].memref.buffer == NULL ||
        params[0].memref.size != TEE_TLS_D_SERVER_KEY_SHARE_SERIALIZED_LEN ||
        params[1].memref.size < TEE_TLS_D_P256_PUBLIC_KEY_LEN) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    state->server_key_share_calls++;
    input = (const uint8_t *) params[0].memref.buffer;
    output = (uint8_t *) params[1].memref.buffer;
    connection_handle = read_u32_le(input + 0);
    named_group = read_u32_le(input + 4);
    public_key_size = read_u32_le(input + 8);

    connection = find_connection(state, connection_handle);
    if (connection == NULL || public_key_size < TEE_TLS_D_P256_PUBLIC_KEY_LEN ||
        named_group != 0x0017U) {
        result = TEE_ERROR_BAD_PARAMETERS;
        goto failure;
    }

    release_ecdhe_keypair(connection);

    result = TEE_AllocateTransientObject(TEE_TYPE_ECDH_KEYPAIR,
                                         256,
                                         &connection->ecdhe_keypair);
    if (result != TEE_SUCCESS) {
        goto failure;
    }

    TEE_InitValueAttribute(&curve_attr,
                           TEE_ATTR_ECC_CURVE,
                           TEE_ECC_CURVE_NIST_P256,
                           0);
    result = TEE_GenerateKey(connection->ecdhe_keypair,
                             256,
                             &curve_attr,
                             1);
    if (result != TEE_SUCCESS) {
        goto failure;
    }

    result = TEE_GetObjectBufferAttribute(connection->ecdhe_keypair,
                                          TEE_ATTR_ECC_PUBLIC_VALUE_X,
                                          x,
                                          &x_len);
    if (result != TEE_SUCCESS) {
        goto failure;
    }
    result = TEE_GetObjectBufferAttribute(connection->ecdhe_keypair,
                                          TEE_ATTR_ECC_PUBLIC_VALUE_Y,
                                          y,
                                          &y_len);
    if (result != TEE_SUCCESS) {
        goto failure;
    }
    /*
     * OP-TEE exports ECC coordinates as unsigned bignums and may omit
     * leading zero octets. TLS/SEC1 uncompressed P-256 points require
     * exactly 32 octets for each coordinate, so left-pad the exported
     * values instead of rejecting valid 31-byte coordinates.
     */
    if (x_len == 0 || x_len > sizeof(x) ||
        y_len == 0 || y_len > sizeof(y)) {
        result = TEE_ERROR_BAD_STATE;
        goto failure;
    }

    output[0] = 0x04U;
    TEE_MemFill(output + 1, 0,
                TEE_TLS_D_P256_PUBLIC_KEY_LEN - 1U);
    TEE_MemMove(output + 1 + (sizeof(x) - x_len),
                x, x_len);
    TEE_MemMove(output + 1 + sizeof(x) + (sizeof(y) - y_len),
                y, y_len);
    params[1].memref.size = TEE_TLS_D_P256_PUBLIC_KEY_LEN;
    connection->has_ecdhe = true;
    state->server_key_share_success++;
    goto cleanup;

failure:
    state->server_key_share_failure++;
    state->failures++;
    release_ecdhe_keypair(connection);

cleanup:
    TEE_MemFill(x, 0, sizeof(x));
    TEE_MemFill(y, 0, sizeof(y));
    return result;
}

static TEE_Result ecdhe_shared_secret_p256(connection_slot_t *connection,
                                           const uint8_t *peer_public_key,
                                           uint32_t peer_public_key_len,
                                           uint8_t shared_secret[TEE_TLS_D_P256_PRIVATE_KEY_LEN],
                                           size_t *shared_secret_len)
{
    TEE_Result result;
    const uint8_t *peer_x;
    const uint8_t *peer_y;
    TEE_OperationHandle operation = TEE_HANDLE_NULL;
    TEE_ObjectHandle secret_object = TEE_HANDLE_NULL;
    TEE_Attribute attrs[2];
    size_t output_len = TEE_TLS_D_P256_PRIVATE_KEY_LEN;

    if (connection == NULL || !connection->has_ecdhe ||
        connection->ecdhe_keypair == TEE_HANDLE_NULL ||
        peer_public_key == NULL || shared_secret == NULL ||
        shared_secret_len == NULL) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    result = parse_p256_public_key(peer_public_key, peer_public_key_len,
                                   &peer_x, &peer_y);
    if (result != TEE_SUCCESS) {
        return result;
    }

    result = TEE_AllocateOperation(&operation,
                                   TEE_ALG_ECDH_P256,
                                   TEE_MODE_DERIVE,
                                   256);
    if (result != TEE_SUCCESS) {
        goto cleanup;
    }

    result = TEE_SetOperationKey(operation, connection->ecdhe_keypair);
    if (result != TEE_SUCCESS) {
        goto cleanup;
    }

    result = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET,
                                         256,
                                         &secret_object);
    if (result != TEE_SUCCESS) {
        goto cleanup;
    }

    TEE_InitRefAttribute(&attrs[0],
                         TEE_ATTR_ECC_PUBLIC_VALUE_X,
                         peer_x,
                         TEE_TLS_D_P256_PRIVATE_KEY_LEN);
    TEE_InitRefAttribute(&attrs[1],
                         TEE_ATTR_ECC_PUBLIC_VALUE_Y,
                         peer_y,
                         TEE_TLS_D_P256_PRIVATE_KEY_LEN);
    TEE_DeriveKey(operation, attrs, 2, secret_object);
    result = TEE_SUCCESS;

    result = TEE_GetObjectBufferAttribute(secret_object,
                                          TEE_ATTR_SECRET_VALUE,
                                          shared_secret,
                                          &output_len);
    if (result == TEE_SUCCESS) {
        *shared_secret_len = output_len;
    }

cleanup:
    if (secret_object != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(secret_object);
    }
    if (operation != TEE_HANDLE_NULL) {
        TEE_FreeOperation(operation);
    }
    return result;
}

static TEE_Result command_handshake_keys(session_state_t *state,
                                         uint32_t param_types,
                                         TEE_Param params[4])
{
    const uint32_t expected =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_VALUE_OUTPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);
    const uint8_t *input;
    connection_slot_t *connection = NULL;
    uint32_t connection_handle;
    uint32_t ciphersuite;
    uint32_t tls_version;
    uint32_t psk_len;
    uint32_t psk_type;
    uint32_t shared_secret_len;
    uint32_t peer_public_key_len;
    uint32_t transcript_len;
    TEE_Result result;
    uint8_t tee_shared_secret[TEE_TLS_D_MAX_SECRET_LEN];
    size_t tee_shared_secret_len = 0;
    const uint8_t *effective_secret;
    size_t effective_secret_len;
    const uint8_t *psk;
    const uint8_t *peer_public_key;
    const uint8_t *transcript;
    uint8_t early_secret[TEE_TLS_D_HASH_LEN_SHA256];
    uint8_t derived_secret[TEE_TLS_D_HASH_LEN_SHA256];
    uint8_t key_enc[16];
    uint8_t key_dec[16];
    uint8_t iv_enc[12];
    uint8_t iv_dec[12];
    uint32_t transform_handle = 0;

    if (state == NULL || param_types != expected ||
        params[0].memref.buffer == NULL ||
        params[0].memref.size != TEE_TLS_D_HANDSHAKE_KEYS_SERIALIZED_LEN) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    state->handshake_key_calls++;
    input = (const uint8_t *) params[0].memref.buffer;
    connection_handle = read_u32_le(input + 0);
    ciphersuite = read_u32_le(input + 4);
    tls_version = read_u32_le(input + 8);
    psk_len = read_u32_le(input + 12);
    psk_type = read_u32_le(input + 16);
    shared_secret_len = read_u32_le(input + 20);
    peer_public_key_len = read_u32_le(input + 24);
    transcript_len = read_u32_le(input + 28);
    psk = input + TEE_TLS_D_HANDSHAKE_KEYS_HEADER_LEN;
    peer_public_key = input + TEE_TLS_D_HANDSHAKE_KEYS_HEADER_LEN +
                      TEE_TLS_D_MAX_PSK_LEN +
                      TEE_TLS_D_MAX_SECRET_LEN;
    transcript = input + TEE_TLS_D_HANDSHAKE_KEYS_HEADER_LEN +
                 TEE_TLS_D_MAX_PSK_LEN +
                 TEE_TLS_D_MAX_SECRET_LEN +
                 TEE_TLS_D_HANDSHAKE_PEER_KEY_MAX_LEN;

    connection = find_connection(state, connection_handle);
    if (connection == NULL ||
        !tee_tls_d_profile_supported(ciphersuite, tls_version) ||
        psk_len > TEE_TLS_D_MAX_PSK_LEN ||
        shared_secret_len > TEE_TLS_D_MAX_SECRET_LEN ||
        peer_public_key_len > TEE_TLS_D_HANDSHAKE_PEER_KEY_MAX_LEN ||
        transcript_len != TEE_TLS_D_HASH_LEN_SHA256 ||
        (shared_secret_len == 0 && peer_public_key_len == 0)) {
        result = TEE_ERROR_BAD_PARAMETERS;
        goto failure;
    }

    (void) psk_type;

    result = evolve_secret_sha256(NULL,
                                  psk_len == 0 ? NULL : psk,
                                  psk_len,
                                  early_secret);
    if (result != TEE_SUCCESS) {
        goto failure;
    }

    if (shared_secret_len != 0) {
        effective_secret = input + TEE_TLS_D_HANDSHAKE_KEYS_HEADER_LEN +
                           TEE_TLS_D_MAX_PSK_LEN;
        effective_secret_len = shared_secret_len;
    } else {
        result = ecdhe_shared_secret_p256(connection,
                                         peer_public_key,
                                         peer_public_key_len,
                                         tee_shared_secret,
                                         &tee_shared_secret_len);
        if (result != TEE_SUCCESS) {
            goto failure;
        }
        effective_secret = tee_shared_secret;
        effective_secret_len = tee_shared_secret_len;
    }

    result = evolve_secret_sha256(
        early_secret,
        effective_secret,
        effective_secret_len,
        connection->handshake_secret);
    if (result != TEE_SUCCESS) {
        goto failure;
    }

    result = derive_secret_sha256(
        connection->handshake_secret,
        "c hs traffic",
        transcript,
        connection->client_hs_secret);
    if (result != TEE_SUCCESS) {
        goto failure;
    }

    result = derive_secret_sha256(
        connection->handshake_secret,
        "s hs traffic",
        transcript,
        connection->server_hs_secret);
    if (result != TEE_SUCCESS) {
        goto failure;
    }

    result = evolve_secret_sha256(connection->handshake_secret,
                                  NULL, 0,
                                  connection->master_secret);
    if (result != TEE_SUCCESS) {
        goto failure;
    }

    result = make_tls13_traffic_key_sha256(connection->server_hs_secret,
                                           key_enc, iv_enc);
    if (result != TEE_SUCCESS) {
        goto failure;
    }
    result = make_tls13_traffic_key_sha256(connection->client_hs_secret,
                                           key_dec, iv_dec);
    if (result != TEE_SUCCESS) {
        goto failure;
    }

    result = allocate_transform_from_keys(state, connection_handle,
                                          key_enc, iv_enc,
                                          key_dec, iv_dec,
                                          &transform_handle);
    if (result != TEE_SUCCESS) {
        goto failure;
    }

    connection->has_handshake = true;
    params[1].value.a = transform_handle;
    params[1].value.b = 0;
    state->handshake_key_success++;
    goto cleanup;

failure:
    state->handshake_key_failure++;
    state->failures++;

cleanup:
    release_ecdhe_keypair(connection);
    TEE_MemFill(tee_shared_secret, 0, sizeof(tee_shared_secret));
    TEE_MemFill(early_secret, 0, sizeof(early_secret));
    TEE_MemFill(derived_secret, 0, sizeof(derived_secret));
    TEE_MemFill(key_enc, 0, sizeof(key_enc));
    TEE_MemFill(key_dec, 0, sizeof(key_dec));
    TEE_MemFill(iv_enc, 0, sizeof(iv_enc));
    TEE_MemFill(iv_dec, 0, sizeof(iv_dec));
    return result;
}

static TEE_Result command_application_keys(session_state_t *state,
                                           uint32_t param_types,
                                           TEE_Param params[4])
{
    const uint32_t expected =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_VALUE_OUTPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);
    const uint8_t *input;
    connection_slot_t *connection;
    uint32_t connection_handle;
    uint32_t ciphersuite;
    uint32_t tls_version;
    uint32_t transcript_len;
    TEE_Result result;
    uint8_t key_enc[16];
    uint8_t key_dec[16];
    uint8_t iv_enc[12];
    uint8_t iv_dec[12];
    uint32_t transform_handle = 0;

    if (state == NULL || param_types != expected ||
        params[0].memref.buffer == NULL ||
        params[0].memref.size != TEE_TLS_D_APPLICATION_KEYS_SERIALIZED_LEN) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    state->application_key_calls++;
    input = (const uint8_t *) params[0].memref.buffer;
    connection_handle = read_u32_le(input + 0);
    ciphersuite = read_u32_le(input + 4);
    tls_version = read_u32_le(input + 8);
    transcript_len = read_u32_le(input + 12);

    connection = find_connection(state, connection_handle);
    if (connection == NULL ||
        !tee_tls_d_profile_supported(ciphersuite, tls_version) || !connection->has_handshake ||
        transcript_len != TEE_TLS_D_HASH_LEN_SHA256) {
        result = TEE_ERROR_BAD_PARAMETERS;
        goto failure;
    }

    result = derive_secret_sha256(
        connection->master_secret,
        "c ap traffic",
        input + TEE_TLS_D_APPLICATION_KEYS_HEADER_LEN,
        connection->client_app_secret);
    if (result != TEE_SUCCESS) {
        goto failure;
    }

    result = derive_secret_sha256(
        connection->master_secret,
        "s ap traffic",
        input + TEE_TLS_D_APPLICATION_KEYS_HEADER_LEN,
        connection->server_app_secret);
    if (result != TEE_SUCCESS) {
        goto failure;
    }

    result = make_tls13_traffic_key_sha256(connection->server_app_secret,
                                           key_enc, iv_enc);
    if (result != TEE_SUCCESS) {
        goto failure;
    }
    result = make_tls13_traffic_key_sha256(connection->client_app_secret,
                                           key_dec, iv_dec);
    if (result != TEE_SUCCESS) {
        goto failure;
    }

    result = allocate_transform_from_keys(state, connection_handle,
                                          key_enc, iv_enc,
                                          key_dec, iv_dec,
                                          &transform_handle);
    if (result != TEE_SUCCESS) {
        goto failure;
    }

    connection->has_application = true;
    params[1].value.a = transform_handle;
    params[1].value.b = 0;
    state->application_key_success++;
    goto cleanup;

failure:
    state->application_key_failure++;
    state->failures++;

cleanup:
    TEE_MemFill(key_enc, 0, sizeof(key_enc));
    TEE_MemFill(key_dec, 0, sizeof(key_dec));
    TEE_MemFill(iv_enc, 0, sizeof(iv_enc));
    TEE_MemFill(iv_dec, 0, sizeof(iv_dec));
    return result;
}

static TEE_Result command_resumption_master(session_state_t *state,
                                            uint32_t param_types,
                                            TEE_Param params[4])
{
    const uint32_t expected =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);
    const uint8_t *input;
    connection_slot_t *connection;
    uint32_t connection_handle;
    uint32_t ciphersuite;
    uint32_t tls_version;
    uint32_t transcript_len;
    TEE_Result result;

    if (state == NULL || param_types != expected ||
        params[0].memref.buffer == NULL ||
        params[0].memref.size != TEE_TLS_D_RESUMPTION_MASTER_SERIALIZED_LEN ||
        params[1].memref.buffer == NULL ||
        params[1].memref.size < TEE_TLS_D_HASH_LEN_SHA256) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    state->resumption_master_calls++;
    input = (const uint8_t *) params[0].memref.buffer;
    connection_handle = read_u32_le(input + 0);
    ciphersuite = read_u32_le(input + 4);
    tls_version = read_u32_le(input + 8);
    transcript_len = read_u32_le(input + 12);

    connection = find_connection(state, connection_handle);
    if (connection == NULL ||
        !tee_tls_d_profile_supported(ciphersuite, tls_version) || !connection->has_application ||
        transcript_len != TEE_TLS_D_HASH_LEN_SHA256) {
        result = TEE_ERROR_BAD_PARAMETERS;
        goto failure;
    }

    result = derive_secret_sha256(
        connection->master_secret,
        "res master",
        input + TEE_TLS_D_RESUMPTION_MASTER_HEADER_LEN,
        connection->resumption_master_secret);
    if (result != TEE_SUCCESS) {
        goto failure;
    }

    TEE_MemMove(params[1].memref.buffer,
                connection->resumption_master_secret,
                TEE_TLS_D_HASH_LEN_SHA256);
    params[1].memref.size = TEE_TLS_D_HASH_LEN_SHA256;
    connection->has_resumption_master = true;
    state->resumption_master_success++;
    return TEE_SUCCESS;

failure:
    state->resumption_master_failure++;
    state->failures++;
    return result;
}

static TEE_Result command_resumption_psk(session_state_t *state,
                                         uint32_t param_types,
                                         TEE_Param params[4])
{
    const uint32_t expected =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);
    const uint8_t *input;
    connection_slot_t *connection;
    uint32_t connection_handle;
    uint32_t ciphersuite;
    uint32_t tls_version;
    uint32_t ticket_nonce_len;
    TEE_Result result;

    if (state == NULL || param_types != expected ||
        params[0].memref.buffer == NULL ||
        params[0].memref.size != TEE_TLS_D_RESUMPTION_PSK_SERIALIZED_LEN ||
        params[1].memref.buffer == NULL ||
        params[1].memref.size < TEE_TLS_D_HASH_LEN_SHA256) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    state->resumption_psk_calls++;
    input = (const uint8_t *) params[0].memref.buffer;
    connection_handle = read_u32_le(input + 0);
    ciphersuite = read_u32_le(input + 4);
    tls_version = read_u32_le(input + 8);
    ticket_nonce_len = read_u32_le(input + 12);

    connection = find_connection(state, connection_handle);
    if (connection == NULL ||
        !tee_tls_d_profile_supported(ciphersuite, tls_version) || !connection->has_resumption_master ||
        ticket_nonce_len > TEE_TLS_D_MAX_TICKET_NONCE_LEN) {
        result = TEE_ERROR_BAD_PARAMETERS;
        goto failure;
    }

    result = hkdf_expand_label_sha256(connection->resumption_master_secret,
                                      "resumption",
                                      input + TEE_TLS_D_RESUMPTION_PSK_HEADER_LEN,
                                      ticket_nonce_len,
                                      params[1].memref.buffer,
                                      TEE_TLS_D_HASH_LEN_SHA256);
    if (result != TEE_SUCCESS) {
        goto failure;
    }

    params[1].memref.size = TEE_TLS_D_HASH_LEN_SHA256;
    state->resumption_psk_success++;
    return TEE_SUCCESS;

failure:
    state->resumption_psk_failure++;
    state->failures++;
    return result;
}

static TEE_Result command_finished(session_state_t *state,
                                   uint32_t param_types,
                                   TEE_Param params[4])
{
    const uint32_t expected =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);
    const uint8_t *input;
    connection_slot_t *connection;
    uint32_t connection_handle;
    uint32_t from;
    uint32_t transcript_len;
    const uint8_t *base_secret;
    TEE_Result result;
    uint8_t finished_key[TEE_TLS_D_HASH_LEN_SHA256];

    if (state == NULL || param_types != expected ||
        params[0].memref.buffer == NULL || params[1].memref.buffer == NULL ||
        params[0].memref.size != TEE_TLS_D_FINISHED_SERIALIZED_LEN ||
        params[1].memref.size < TEE_TLS_D_HASH_LEN_SHA256) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    state->finished_calls++;
    input = (const uint8_t *) params[0].memref.buffer;
    connection_handle = read_u32_le(input + 0);
    from = read_u32_le(input + 4);
    transcript_len = read_u32_le(input + 8);

    connection = find_connection(state, connection_handle);
    if (connection == NULL || !connection->has_handshake ||
        transcript_len != TEE_TLS_D_HASH_LEN_SHA256) {
        result = TEE_ERROR_BAD_PARAMETERS;
        goto failure;
    }

    if (from == 0) {
        base_secret = connection->client_hs_secret;
    } else {
        base_secret = connection->server_hs_secret;
    }

    result = hkdf_expand_label_sha256(base_secret, "finished", NULL, 0,
                                      finished_key,
                                      sizeof(finished_key));
    if (result != TEE_SUCCESS) {
        goto failure;
    }

    result = hmac_sha256(finished_key,
                         sizeof(finished_key),
                         input + TEE_TLS_D_FINISHED_HEADER_LEN,
                         TEE_TLS_D_HASH_LEN_SHA256,
                         (uint8_t *) params[1].memref.buffer);
    if (result != TEE_SUCCESS) {
        goto failure;
    }

    params[1].memref.size = TEE_TLS_D_HASH_LEN_SHA256;
    state->finished_success++;
    goto cleanup;

failure:
    state->finished_failure++;
    state->failures++;

cleanup:
    TEE_MemFill(finished_key, 0, sizeof(finished_key));
    return result;
}

static TEE_Result command_get_stats(session_state_t *state,
                                    uint32_t param_types,
                                    TEE_Param params[4])
{
    const uint32_t expected =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);
    uint8_t *output;

    if (state == NULL ||
        param_types != expected ||
        params[0].memref.buffer == NULL ||
        params[0].memref.size < TEE_TLS_D_STATS_SERIALIZED_LEN) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    output = (uint8_t *) params[0].memref.buffer;
    write_u64_le(output + 0, state->connection_open_calls);
    write_u64_le(output + 8, state->connection_close_calls);
    write_u64_le(output + 16, state->active_connections);
    write_u64_le(output + 24, state->peak_active_connections);
    write_u64_le(output + 32, state->selftest_calls);
    write_u64_le(output + 40, state->failures);
    write_u64_le(output + 48, state->transform_import_calls);
    write_u64_le(output + 56, state->transform_import_success);
    write_u64_le(output + 64, state->transform_import_failure);
    write_u64_le(output + 72, state->transform_free_calls);
    write_u64_le(output + 80, state->transform_free_success);
    write_u64_le(output + 88, state->transform_free_failure);
    write_u64_le(output + 96, state->record_seal_calls);
    write_u64_le(output + 104, state->record_seal_success);
    write_u64_le(output + 112, state->record_seal_failure);
    write_u64_le(output + 120, state->record_open_calls);
    write_u64_le(output + 128, state->record_open_success);
    write_u64_le(output + 136, state->record_open_failure);
    write_u64_le(output + 144, state->handshake_key_calls);
    write_u64_le(output + 152, state->handshake_key_success);
    write_u64_le(output + 160, state->handshake_key_failure);
    write_u64_le(output + 168, state->application_key_calls);
    write_u64_le(output + 176, state->application_key_success);
    write_u64_le(output + 184, state->application_key_failure);
    write_u64_le(output + 192, state->finished_calls);
    write_u64_le(output + 200, state->finished_success);
    write_u64_le(output + 208, state->finished_failure);
    write_u64_le(output + 216, state->server_key_share_calls);
    write_u64_le(output + 224, state->server_key_share_success);
    write_u64_le(output + 232, state->server_key_share_failure);
    write_u64_le(output + 240, state->resumption_master_calls);
    write_u64_le(output + 248, state->resumption_master_success);
    write_u64_le(output + 256, state->resumption_master_failure);
    write_u64_le(output + 264, state->resumption_psk_calls);
    write_u64_le(output + 272, state->resumption_psk_success);
    write_u64_le(output + 280, state->resumption_psk_failure);
    params[0].memref.size = TEE_TLS_D_STATS_SERIALIZED_LEN;
    return TEE_SUCCESS;
}

static TEE_Result command_reset_stats(session_state_t *state,
                                      uint32_t param_types,
                                      TEE_Param params[4])
{
    const uint32_t expected =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);

    (void) params;

    if (state == NULL || param_types != expected) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (state->active_connections != 0) {
        return TEE_ERROR_BAD_STATE;
    }

    state->connection_open_calls = 0;
    state->connection_close_calls = 0;
    state->peak_active_connections = 0;
    state->selftest_calls = 0;
    state->failures = 0;
    state->transform_import_calls = 0;
    state->transform_import_success = 0;
    state->transform_import_failure = 0;
    state->transform_free_calls = 0;
    state->transform_free_success = 0;
    state->transform_free_failure = 0;
    state->record_seal_calls = 0;
    state->record_seal_success = 0;
    state->record_seal_failure = 0;
    state->record_open_calls = 0;
    state->record_open_success = 0;
    state->record_open_failure = 0;
    state->handshake_key_calls = 0;
    state->handshake_key_success = 0;
    state->handshake_key_failure = 0;
    state->application_key_calls = 0;
    state->application_key_success = 0;
    state->application_key_failure = 0;
    state->finished_calls = 0;
    state->finished_success = 0;
    state->finished_failure = 0;
    state->server_key_share_calls = 0;
    state->server_key_share_success = 0;
    state->server_key_share_failure = 0;
    state->resumption_master_calls = 0;
    state->resumption_master_success = 0;
    state->resumption_master_failure = 0;
    state->resumption_psk_calls = 0;
    state->resumption_psk_success = 0;
    state->resumption_psk_failure = 0;
    return TEE_SUCCESS;
}

TEE_Result TA_CreateEntryPoint(void)
{
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                    TEE_Param params[4],
                                    void **session_context)
{
    const uint32_t expected =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);
    session_state_t *state;

    (void) params;

    if (session_context == NULL || param_types != expected) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    state = TEE_Malloc(sizeof(*state), TEE_MALLOC_FILL_ZERO);
    if (state == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    state->next_connection_handle = 1;
    state->next_transform_handle = 1;
    *session_context = state;
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session_context)
{
    session_state_t *state = (session_state_t *) session_context;

    if (state == NULL) {
        return;
    }

    for (size_t i = 0; i < TEE_TLS_D_MAX_CONNECTIONS; ++i) {
        if (state->connections[i].ecdhe_keypair != TEE_HANDLE_NULL) {
            TEE_FreeTransientObject(state->connections[i].ecdhe_keypair);
            state->connections[i].ecdhe_keypair = TEE_HANDLE_NULL;
        }
    }

    TEE_MemFill(state, 0, sizeof(*state));
    TEE_Free(state);
}

TEE_Result TA_InvokeCommandEntryPoint(void *session_context,
                                      uint32_t command_id,
                                      uint32_t param_types,
                                      TEE_Param params[4])
{
    session_state_t *state = (session_state_t *) session_context;

    switch (command_id) {
        case TA_TLS_D_CMD_GET_CAPS:
            return command_get_caps(param_types, params);

        case TA_TLS_D_CMD_SELFTEST:
            return command_selftest(state, param_types, params);

        case TA_TLS_D_CMD_CONNECTION_OPEN:
            return command_connection_open(state, param_types, params);

        case TA_TLS_D_CMD_CONNECTION_CLOSE:
            return command_connection_close(state, param_types, params);

        case TA_TLS_D_CMD_GET_STATS:
            return command_get_stats(state, param_types, params);

        case TA_TLS_D_CMD_RESET_STATS:
            return command_reset_stats(state, param_types, params);

        case TA_TLS_D_CMD_TRANSFORM_IMPORT:
            return command_transform_import(state, param_types, params);

        case TA_TLS_D_CMD_TRANSFORM_FREE:
            return command_transform_free(state, param_types, params);

        case TA_TLS_D_CMD_RECORD_SEAL:
            return command_record_seal(state, param_types, params);

        case TA_TLS_D_CMD_RECORD_OPEN:
            return command_record_open(state, param_types, params);

        case TA_TLS_D_CMD_HANDSHAKE_KEYS:
            return command_handshake_keys(state, param_types, params);

        case TA_TLS_D_CMD_APPLICATION_KEYS:
            return command_application_keys(state, param_types, params);

        case TA_TLS_D_CMD_FINISHED:
            return command_finished(state, param_types, params);

        case TA_TLS_D_CMD_SERVER_KEY_SHARE:
            return command_server_key_share(state, param_types, params);

        case TA_TLS_D_CMD_RESUMPTION_MASTER:
            return command_resumption_master(state, param_types, params);

        case TA_TLS_D_CMD_RESUMPTION_PSK:
            return command_resumption_psk(state, param_types, params);

        default:
            EMSG("unsupported command id=%" PRIu32, command_id);
            return TEE_ERROR_NOT_SUPPORTED;
    }
}
