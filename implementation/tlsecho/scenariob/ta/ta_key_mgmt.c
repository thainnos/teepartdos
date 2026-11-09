#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <ta_key_mgmt.h>

#define KM_BLOB_MAGIC0 0x42U /* B */
#define KM_BLOB_MAGIC1 0x4bU /* K */
#define KM_BLOB_MAGIC2 0x4dU /* M */
#define KM_BLOB_MAGIC3 0x31U /* 1 */
#define KM_BLOB_VERSION 1U
#define KM_AES_KEY_BITS 256U
#define KM_AES_KEY_BYTES 32U

static uint8_t g_kek[KM_AES_KEY_BYTES];
static bool g_kek_ready;

static uint64_t g_derive_calls;
static uint64_t g_wrap_calls;
static uint64_t g_unwrap_calls;
static uint64_t g_failures;

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           ((uint32_t)p[3]);
}

static TEE_Result ensure_kek(void)
{
    if (!g_kek_ready) {
        TEE_GenerateRandom(g_kek, sizeof(g_kek));
        g_kek_ready = true;
    }
    return TEE_SUCCESS;
}

static void account_failure(TEE_Result res)
{
    if (res != TEE_SUCCESS) {
        g_failures++;
    }
}

static TEE_Result setup_aes_gcm(TEE_OperationHandle *op,
                                TEE_ObjectHandle *key,
                                uint32_t mode)
{
    TEE_Result res;
    TEE_Attribute attr;

    *op = TEE_HANDLE_NULL;
    *key = TEE_HANDLE_NULL;

    res = ensure_kek();
    if (res != TEE_SUCCESS) {
        return res;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_AES, KM_AES_KEY_BITS, key);
    if (res != TEE_SUCCESS) {
        return res;
    }

    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, g_kek, sizeof(g_kek));
    res = TEE_PopulateTransientObject(*key, &attr, 1);
    if (res != TEE_SUCCESS) {
        TEE_FreeTransientObject(*key);
        *key = TEE_HANDLE_NULL;
        return res;
    }

    res = TEE_AllocateOperation(op, TEE_ALG_AES_GCM, mode, KM_AES_KEY_BITS);
    if (res != TEE_SUCCESS) {
        TEE_FreeTransientObject(*key);
        *key = TEE_HANDLE_NULL;
        return res;
    }

    res = TEE_SetOperationKey(*op, *key);
    if (res != TEE_SUCCESS) {
        TEE_FreeOperation(*op);
        TEE_FreeTransientObject(*key);
        *op = TEE_HANDLE_NULL;
        *key = TEE_HANDLE_NULL;
    }

    return res;
}

static TEE_Result cmd_init(uint32_t param_types, TEE_Param params[4])
{
    (void)params;
    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return ensure_kek();
}

static TEE_Result cmd_derive_session_token(uint32_t param_types, TEE_Param params[4])
{
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    uint8_t *in;
    size_t in_len;
    uint8_t *out;
    size_t out_len;

    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                       TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    in = params[0].memref.buffer;
    in_len = params[0].memref.size;
    out = params[1].memref.buffer;
    out_len = params[1].memref.size;

    if (!in || !out || out_len < TA_KM_TOKEN_LEN) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = ensure_kek();
    if (res != TEE_SUCCESS) {
        account_failure(res);
        return res;
    }

    /* Prototype KDF: SHA-256(TEE-held KEK || caller-provided session context).
     * This intentionally keeps the root material TEE-resident. For production use,
     * replace this with an approved KDF/HMAC construction and explicit labels. */
    res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS) {
        account_failure(res);
        return res;
    }

    TEE_DigestUpdate(op, g_kek, sizeof(g_kek));
    out_len = TA_KM_TOKEN_LEN;
    res = TEE_DigestDoFinal(op, in, in_len, out, &out_len);
    TEE_FreeOperation(op);

    if (res == TEE_SUCCESS) {
        params[1].memref.size = out_len;
        g_derive_calls++;
    } else {
        account_failure(res);
    }
    return res;
}

static TEE_Result cmd_wrap_session_state(uint32_t param_types, TEE_Param params[4])
{
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_ObjectHandle key = TEE_HANDLE_NULL;
    uint8_t *plain;
    size_t plain_len;
    uint8_t *blob;
    size_t blob_cap;
    size_t cipher_len;
    size_t tag_len = TA_KM_AES_GCM_TAG_LEN;
    size_t needed;
    uint8_t *hdr;
    uint8_t *nonce;
    uint8_t *cipher;
    uint8_t *tag;

    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                       TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    plain = params[0].memref.buffer;
    plain_len = params[0].memref.size;
    blob = params[1].memref.buffer;
    blob_cap = params[1].memref.size;

    if (!plain || !blob || plain_len == 0 || plain_len > TA_KM_MAX_PLAINTEXT_LEN) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    needed = TA_KM_BLOB_HEADER_LEN + TA_KM_AES_GCM_NONCE_LEN + plain_len + TA_KM_AES_GCM_TAG_LEN;
    if (blob_cap < needed) {
        params[1].memref.size = needed;
        return TEE_ERROR_SHORT_BUFFER;
    }

    hdr = blob;
    nonce = blob + TA_KM_BLOB_HEADER_LEN;
    cipher = nonce + TA_KM_AES_GCM_NONCE_LEN;
    tag = cipher + plain_len;

    memset(hdr, 0, TA_KM_BLOB_HEADER_LEN);
    hdr[0] = KM_BLOB_MAGIC0;
    hdr[1] = KM_BLOB_MAGIC1;
    hdr[2] = KM_BLOB_MAGIC2;
    hdr[3] = KM_BLOB_MAGIC3;
    hdr[4] = KM_BLOB_VERSION;
    hdr[5] = 0U;
    hdr[6] = 0U;
    hdr[7] = TA_KM_AES_GCM_NONCE_LEN;
    hdr[8] = 0U;
    hdr[9] = TA_KM_AES_GCM_TAG_LEN;
    put_be32(hdr + 10, (uint32_t)plain_len);
    hdr[14] = 0U;
    hdr[15] = 0U;

    TEE_GenerateRandom(nonce, TA_KM_AES_GCM_NONCE_LEN);

    res = setup_aes_gcm(&op, &key, TEE_MODE_ENCRYPT);
    if (res != TEE_SUCCESS) {
        account_failure(res);
        return res;
    }

    TEE_AEInit(op, nonce, TA_KM_AES_GCM_NONCE_LEN,
               TA_KM_AES_GCM_TAG_LEN * 8U,
               TA_KM_BLOB_HEADER_LEN + TA_KM_AES_GCM_NONCE_LEN,
               plain_len);
    TEE_AEUpdateAAD(op, hdr, TA_KM_BLOB_HEADER_LEN + TA_KM_AES_GCM_NONCE_LEN);

    cipher_len = plain_len;
    res = TEE_AEEncryptFinal(op, plain, plain_len, cipher, &cipher_len, tag, &tag_len);
    if (res != TEE_SUCCESS) {
        EMSG("wrap AES-GCM failed: res=0x%08" PRIx32 " plain_len=%zu blob_cap=%zu",
             (uint32_t)res, plain_len, blob_cap);
    }

    TEE_FreeOperation(op);
    TEE_FreeTransientObject(key);

    if (res == TEE_SUCCESS) {
        params[1].memref.size = TA_KM_BLOB_HEADER_LEN + TA_KM_AES_GCM_NONCE_LEN + cipher_len + tag_len;
        g_wrap_calls++;
    } else {
        account_failure(res);
    }
    return res;
}

static TEE_Result cmd_unwrap_session_state(uint32_t param_types, TEE_Param params[4])
{
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_ObjectHandle key = TEE_HANDLE_NULL;
    uint8_t *blob;
    size_t blob_len;
    uint8_t *plain;
    size_t plain_cap;
    size_t plain_len;
    size_t tag_len;
    uint8_t *hdr;
    uint8_t *nonce;
    uint8_t *cipher;
    uint8_t *tag;

    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                       TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    blob = params[0].memref.buffer;
    blob_len = params[0].memref.size;
    plain = params[1].memref.buffer;
    plain_cap = params[1].memref.size;

    if (!blob || !plain || blob_len < TA_KM_BLOB_OVERHEAD_LEN) {
        EMSG("unwrap rejected: bad parameters blob_len=%zu plain_cap=%zu", blob_len, plain_cap);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    hdr = blob;
    if (hdr[0] != KM_BLOB_MAGIC0 || hdr[1] != KM_BLOB_MAGIC1 ||
        hdr[2] != KM_BLOB_MAGIC2 || hdr[3] != KM_BLOB_MAGIC3 ||
        hdr[4] != KM_BLOB_VERSION || hdr[7] != TA_KM_AES_GCM_NONCE_LEN ||
        hdr[9] != TA_KM_AES_GCM_TAG_LEN) {
        EMSG("unwrap rejected: invalid blob header blob_len=%zu", blob_len);
        return TEE_ERROR_BAD_FORMAT;
    }

    plain_len = get_be32(hdr + 10);
    tag_len = TA_KM_AES_GCM_TAG_LEN;
    if (plain_len == 0 || plain_len > TA_KM_MAX_PLAINTEXT_LEN) {
        EMSG("unwrap rejected: invalid plaintext length=%zu", plain_len);
        return TEE_ERROR_BAD_FORMAT;
    }
    if (blob_len != TA_KM_BLOB_HEADER_LEN + TA_KM_AES_GCM_NONCE_LEN + plain_len + TA_KM_AES_GCM_TAG_LEN) {
        EMSG("unwrap rejected: inconsistent blob length=%zu plaintext length=%zu", blob_len, plain_len);
        return TEE_ERROR_BAD_FORMAT;
    }
    if (plain_cap < plain_len) {
        params[1].memref.size = plain_len;
        return TEE_ERROR_SHORT_BUFFER;
    }

    nonce = blob + TA_KM_BLOB_HEADER_LEN;
    cipher = nonce + TA_KM_AES_GCM_NONCE_LEN;
    tag = cipher + plain_len;

    res = setup_aes_gcm(&op, &key, TEE_MODE_DECRYPT);
    if (res != TEE_SUCCESS) {
        account_failure(res);
        return res;
    }

    TEE_AEInit(op, nonce, TA_KM_AES_GCM_NONCE_LEN,
               TA_KM_AES_GCM_TAG_LEN * 8U,
               TA_KM_BLOB_HEADER_LEN + TA_KM_AES_GCM_NONCE_LEN,
               plain_len);
    TEE_AEUpdateAAD(op, hdr, TA_KM_BLOB_HEADER_LEN + TA_KM_AES_GCM_NONCE_LEN);

    res = TEE_AEDecryptFinal(op, cipher, plain_len, plain, &plain_cap, tag, tag_len);
    if (res != TEE_SUCCESS) {
        EMSG("unwrap AES-GCM failed: res=0x%08" PRIx32 " blob_len=%zu plain_len=%zu output_cap=%zu",
             (uint32_t)res, blob_len, plain_len, params[1].memref.size);
    }

    TEE_FreeOperation(op);
    TEE_FreeTransientObject(key);

    if (res == TEE_SUCCESS) {
        params[1].memref.size = plain_cap;
        g_unwrap_calls++;
    } else {
        account_failure(res);
    }
    return res;
}

static TEE_Result cmd_reset_stats(uint32_t param_types, TEE_Param params[4])
{
    (void)params;
    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    g_derive_calls = 0;
    g_wrap_calls = 0;
    g_unwrap_calls = 0;
    g_failures = 0;
    return TEE_SUCCESS;
}

static void write_u64_le(uint8_t *p, uint64_t v)
{
    for (size_t i = 0; i < 8; ++i) {
        p[i] = (uint8_t)(v >> (8U * i));
    }
}

static TEE_Result cmd_get_stats(uint32_t param_types, TEE_Param params[4])
{
    uint8_t *out;
    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (!params[0].memref.buffer || params[0].memref.size < 32U) {
        params[0].memref.size = 32U;
        return TEE_ERROR_SHORT_BUFFER;
    }
    out = params[0].memref.buffer;
    write_u64_le(out + 0, g_derive_calls);
    write_u64_le(out + 8, g_wrap_calls);
    write_u64_le(out + 16, g_unwrap_calls);
    write_u64_le(out + 24, g_failures);
    params[0].memref.size = 32U;
    return TEE_SUCCESS;
}

TEE_Result TA_CreateEntryPoint(void)
{
    return ensure_kek();
}

void TA_DestroyEntryPoint(void)
{
    memset(g_kek, 0, sizeof(g_kek));
    g_kek_ready = false;
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                    TEE_Param params[4],
                                    void **sess_ctx)
{
    (void)params;
    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    *sess_ctx = NULL;
    return ensure_kek();
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    (void)sess_ctx;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
                                      uint32_t cmd_id,
                                      uint32_t param_types,
                                      TEE_Param params[4])
{
    (void)sess_ctx;

    switch (cmd_id) {
    case TA_KM_CMD_INIT:
        return cmd_init(param_types, params);
    case TA_KM_CMD_DERIVE_SESSION_TOKEN:
        return cmd_derive_session_token(param_types, params);
    case TA_KM_CMD_WRAP_SESSION_STATE:
        return cmd_wrap_session_state(param_types, params);
    case TA_KM_CMD_UNWRAP_SESSION_STATE:
        return cmd_unwrap_session_state(param_types, params);
    case TA_KM_CMD_RESET_STATS:
        return cmd_reset_stats(param_types, params);
    case TA_KM_CMD_GET_STATS:
        return cmd_get_stats(param_types, params);
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
