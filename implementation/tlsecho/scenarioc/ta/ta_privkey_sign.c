#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <inttypes.h>
#include <string.h>
#include <ta_privkey_sign.h>

static TEE_ObjectHandle g_key = TEE_HANDLE_NULL;
static bool g_key_loaded;

static uint64_t g_import_calls;
static uint64_t g_sign_calls;
static uint64_t g_failures;

static void write_u64_le(uint8_t *p, uint64_t v)
{
    for (size_t i = 0; i < 8; ++i)
        p[i] = (uint8_t)((v >> (8U * i)) & 0xffU);
}

static TEE_Result cmd_import_key(uint32_t param_types, TEE_Param params[4])
{
    const uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                         TEE_PARAM_TYPE_NONE,
                                         TEE_PARAM_TYPE_NONE,
                                         TEE_PARAM_TYPE_NONE);
    const uint8_t *blob;
    TEE_ObjectHandle key = TEE_HANDLE_NULL;
    TEE_Attribute attrs[4];
    TEE_Result res;

    g_import_calls++;

    if (param_types != exp) {
        EMSG("import: unexpected parameter types 0x%" PRIx32, param_types);
        g_failures++;
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (!params[0].memref.buffer || params[0].memref.size != TEE_SIGN_P256_KEY_BLOB_LEN) {
        EMSG("import: invalid key blob size=%zu", params[0].memref.size);
        g_failures++;
        return TEE_ERROR_BAD_PARAMETERS;
    }

    blob = (const uint8_t *)params[0].memref.buffer;

    res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, 256, &key);
    if (res != TEE_SUCCESS) {
        EMSG("import: TEE_AllocateTransientObject failed res=0x%" PRIx32, res);
        g_failures++;
        return res;
    }

    TEE_InitRefAttribute(&attrs[0], TEE_ATTR_ECC_PRIVATE_VALUE, (void *)(blob + 0), 32);
    TEE_InitRefAttribute(&attrs[1], TEE_ATTR_ECC_PUBLIC_VALUE_X, (void *)(blob + 32), 32);
    TEE_InitRefAttribute(&attrs[2], TEE_ATTR_ECC_PUBLIC_VALUE_Y, (void *)(blob + 64), 32);
    TEE_InitValueAttribute(&attrs[3], TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_NIST_P256, 0);

    res = TEE_PopulateTransientObject(key, attrs, 4);
    if (res != TEE_SUCCESS) {
        EMSG("import: TEE_PopulateTransientObject failed res=0x%" PRIx32, res);
        TEE_FreeTransientObject(key);
        g_failures++;
        return res;
    }

    if (g_key != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(g_key);
    }
    g_key = key;
    g_key_loaded = true;
    return TEE_SUCCESS;
}

static TEE_Result cmd_sign_digest(uint32_t param_types, TEE_Param params[4])
{
    const uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                         TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                         TEE_PARAM_TYPE_NONE,
                                         TEE_PARAM_TYPE_NONE);
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_Result res;
    size_t sig_len;

    g_sign_calls++;

    if (param_types != exp) {
        EMSG("sign: unexpected parameter types 0x%" PRIx32, param_types);
        g_failures++;
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (!g_key_loaded || g_key == TEE_HANDLE_NULL) {
        EMSG("sign: private key is not loaded");
        g_failures++;
        return TEE_ERROR_BAD_STATE;
    }
    if (!params[0].memref.buffer || params[0].memref.size != TEE_SIGN_SHA256_DIGEST_LEN ||
        !params[1].memref.buffer || params[1].memref.size < TEE_SIGN_ECDSA_P256_RAW_SIG_LEN) {
        EMSG("sign: invalid digest/output sizes digest=%zu output=%zu",
             params[0].memref.size, params[1].memref.size);
        g_failures++;
        return TEE_ERROR_BAD_PARAMETERS;
    }

    sig_len = params[1].memref.size;

    res = TEE_AllocateOperation(&op, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, 256);
    if (res != TEE_SUCCESS) {
        EMSG("sign: TEE_AllocateOperation failed res=0x%" PRIx32, res);
        g_failures++;
        return res;
    }

    res = TEE_SetOperationKey(op, g_key);
    if (res != TEE_SUCCESS) {
        EMSG("sign: TEE_SetOperationKey failed res=0x%" PRIx32, res);
        TEE_FreeOperation(op);
        g_failures++;
        return res;
    }

    res = TEE_AsymmetricSignDigest(op,
                                   NULL,
                                   0,
                                   params[0].memref.buffer,
                                   params[0].memref.size,
                                   params[1].memref.buffer,
                                   &sig_len);
    TEE_FreeOperation(op);

    if (res != TEE_SUCCESS) {
        EMSG("sign: TEE_AsymmetricSignDigest failed res=0x%" PRIx32, res);
        g_failures++;
        return res;
    }

    params[1].memref.size = sig_len;
    return TEE_SUCCESS;
}

static TEE_Result cmd_get_stats(uint32_t param_types, TEE_Param params[4])
{
    const uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                         TEE_PARAM_TYPE_NONE,
                                         TEE_PARAM_TYPE_NONE,
                                         TEE_PARAM_TYPE_NONE);
    uint8_t *out;

    if (param_types != exp || !params[0].memref.buffer || params[0].memref.size < 24U) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    out = (uint8_t *)params[0].memref.buffer;
    write_u64_le(out + 0, g_import_calls);
    write_u64_le(out + 8, g_sign_calls);
    write_u64_le(out + 16, g_failures);
    params[0].memref.size = 24U;
    return TEE_SUCCESS;
}

static TEE_Result cmd_reset_stats(uint32_t param_types, TEE_Param params[4])
{
    const uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                         TEE_PARAM_TYPE_NONE,
                                         TEE_PARAM_TYPE_NONE,
                                         TEE_PARAM_TYPE_NONE);
    (void)params;

    if (param_types != exp) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    g_import_calls = 0;
    g_sign_calls = 0;
    g_failures = 0;
    return TEE_SUCCESS;
}

TEE_Result TA_CreateEntryPoint(void)
{
    g_key = TEE_HANDLE_NULL;
    g_key_loaded = false;
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    if (g_key != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(g_key);
        g_key = TEE_HANDLE_NULL;
    }
    g_key_loaded = false;
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                    TEE_Param params[4],
                                    void **sess_ctx)
{
    (void)param_types;
    (void)params;
    (void)sess_ctx;
    return TEE_SUCCESS;
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
    case TA_SIGN_CMD_IMPORT_P256_KEY:
        return cmd_import_key(param_types, params);
    case TA_SIGN_CMD_SIGN_DIGEST:
        return cmd_sign_digest(param_types, params);
    case TA_SIGN_CMD_GET_STATS:
        return cmd_get_stats(param_types, params);
    case TA_SIGN_CMD_RESET_STATS:
        return cmd_reset_stats(param_types, params);
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
