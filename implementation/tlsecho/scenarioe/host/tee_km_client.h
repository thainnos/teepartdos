#ifndef TEE_KM_CLIENT_H
#define TEE_KM_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TEE_KM_TOKEN_LEN 32U

typedef struct {
    bool opened;
    void *ctx_opaque;
    void *sess_opaque;
} tee_km_client_t;

typedef struct {
    uint64_t derive_calls;
    uint64_t wrap_calls;
    uint64_t unwrap_calls;
    uint64_t failures;
} tee_km_ta_stats_t;

typedef struct {
    uint32_t command_id;
    uint32_t result;
    uint32_t origin;
} tee_km_last_error_t;

int tee_km_open(tee_km_client_t *km);
void tee_km_close(tee_km_client_t *km);

int tee_km_init_root(tee_km_client_t *km, uint64_t *duration_us);
int tee_km_reset_stats(tee_km_client_t *km);
int tee_km_get_stats(tee_km_client_t *km, tee_km_ta_stats_t *stats);
int tee_km_get_last_error(const tee_km_client_t *km, tee_km_last_error_t *error);
const char *tee_km_result_name(uint32_t result);
const char *tee_km_origin_name(uint32_t origin);

int tee_km_derive_session_token(tee_km_client_t *km,
                                const unsigned char *context,
                                size_t context_len,
                                unsigned char token[TEE_KM_TOKEN_LEN],
                                size_t *token_len,
                                uint64_t *duration_us);

int tee_km_wrap_session_state(tee_km_client_t *km,
                              const unsigned char *plain,
                              size_t plain_len,
                              unsigned char *blob,
                              size_t blob_cap,
                              size_t *blob_len,
                              uint64_t *duration_us);

int tee_km_unwrap_session_state(tee_km_client_t *km,
                                const unsigned char *blob,
                                size_t blob_len,
                                unsigned char *plain,
                                size_t plain_cap,
                                size_t *plain_len,
                                uint64_t *duration_us);

#endif /* TEE_KM_CLIENT_H */
