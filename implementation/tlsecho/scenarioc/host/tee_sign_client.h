#ifndef TEE_SIGN_CLIENT_H
#define TEE_SIGN_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ta_privkey_sign.h"

typedef struct {
    bool opened;
    void *ctx_opaque;
    void *sess_opaque;
} tee_sign_client_t;

typedef struct {
    uint32_t command;
    uint32_t result;
    uint32_t origin;
} tee_sign_error_t;

typedef struct {
    uint64_t import_calls;
    uint64_t sign_calls;
    uint64_t failures;
} tee_sign_ta_stats_t;

int tee_sign_open(tee_sign_client_t *sgn);
void tee_sign_close(tee_sign_client_t *sgn);

int tee_sign_import_p256_key(tee_sign_client_t *sgn,
                             const unsigned char *key_blob,
                             size_t key_blob_len,
                             uint64_t *duration_us);

int tee_sign_sign_digest(tee_sign_client_t *sgn,
                         const unsigned char *digest,
                         size_t digest_len,
                         unsigned char *signature,
                         size_t signature_cap,
                         size_t *signature_len,
                         uint64_t *duration_us);

int tee_sign_get_stats(tee_sign_client_t *sgn, tee_sign_ta_stats_t *stats);
int tee_sign_get_last_error(tee_sign_client_t *sgn, tee_sign_error_t *error);
int tee_sign_reset_stats(tee_sign_client_t *sgn);

#endif /* TEE_SIGN_CLIENT_H */
