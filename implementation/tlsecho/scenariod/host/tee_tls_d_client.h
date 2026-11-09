#ifndef TEE_TLS_D_CLIENT_H
#define TEE_TLS_D_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ta_tls_d_backend.h"

typedef struct {
    bool opened;
    void *internal;
} tee_tls_d_client_t;

typedef struct {
    uint32_t command;
    uint32_t result;
    uint32_t origin;
} tee_tls_d_error_t;

typedef struct {
    uint32_t api_version;
    uint32_t capabilities;
    uint32_t max_connections;
} tee_tls_d_caps_t;

typedef struct {
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
} tee_tls_d_stats_t;

typedef struct {
    uint32_t connection_handle;
    uint16_t ciphersuite;
    uint16_t tls_version;
    size_t tag_len;
    const unsigned char *key_enc;
    size_t key_enc_len;
    const unsigned char *iv_enc;
    size_t iv_enc_len;
    const unsigned char *key_dec;
    size_t key_dec_len;
    const unsigned char *iv_dec;
    size_t iv_dec_len;
} tee_tls_d_transform_params_t;

typedef struct {
    uint32_t connection_handle;
    uint16_t ciphersuite;
    uint16_t tls_version;
    const unsigned char *psk;
    size_t psk_len;
    int psk_type;
    const unsigned char *shared_secret;
    size_t shared_secret_len;
    const unsigned char *peer_public_key;
    size_t peer_public_key_len;
    const unsigned char *transcript;
    size_t transcript_len;
} tee_tls_d_handshake_keys_params_t;

typedef struct {
    uint32_t connection_handle;
    uint16_t ciphersuite;
    uint16_t tls_version;
    const unsigned char *transcript;
    size_t transcript_len;
} tee_tls_d_application_keys_params_t;


typedef struct {
    uint32_t connection_handle;
    uint16_t named_group;
    unsigned char *public_key;
    size_t public_key_size;
    size_t *public_key_len;
} tee_tls_d_server_key_share_params_t;
typedef struct {
    uint32_t connection_handle;
    uint16_t ciphersuite;
    uint16_t tls_version;
    const unsigned char *transcript;
    size_t transcript_len;
    unsigned char *resumption_master;
    size_t resumption_master_size;
    size_t *resumption_master_len;
} tee_tls_d_resumption_master_params_t;

typedef struct {
    uint32_t connection_handle;
    uint16_t ciphersuite;
    uint16_t tls_version;
    const unsigned char *ticket_nonce;
    size_t ticket_nonce_len;
    unsigned char *resumption_psk;
    size_t resumption_psk_size;
    size_t *resumption_psk_len;
} tee_tls_d_resumption_psk_params_t;

typedef struct {
    uint32_t connection_handle;
    int from;
    const unsigned char *transcript;
    size_t transcript_len;
    unsigned char *verify_data;
    size_t verify_data_size;
    size_t *verify_data_len;
} tee_tls_d_finished_params_t;

int tee_tls_d_open(tee_tls_d_client_t *client);
void tee_tls_d_close(tee_tls_d_client_t *client);

int tee_tls_d_get_caps(tee_tls_d_client_t *client,
                       tee_tls_d_caps_t *caps);

int tee_tls_d_selftest(tee_tls_d_client_t *client,
                       uint64_t *duration_us);

int tee_tls_d_connection_open(tee_tls_d_client_t *client,
                              uint32_t *connection_handle,
                              uint64_t *duration_us);

int tee_tls_d_connection_close(tee_tls_d_client_t *client,
                               uint32_t connection_handle,
                               uint64_t *duration_us);

int tee_tls_d_transform_import(tee_tls_d_client_t *client,
                               const tee_tls_d_transform_params_t *params,
                               uint32_t *transform_handle,
                               uint64_t *duration_us);

int tee_tls_d_transform_free(tee_tls_d_client_t *client,
                             uint32_t transform_handle,
                             uint64_t *duration_us);

int tee_tls_d_record_seal(tee_tls_d_client_t *client,
                          uint32_t transform_handle,
                          const unsigned char *aad,
                          size_t aad_len,
                          const unsigned char *plaintext,
                          size_t plaintext_len,
                          unsigned char *ciphertext,
                          size_t ciphertext_size,
                          size_t *ciphertext_len,
                          uint64_t *duration_us);

int tee_tls_d_record_open(tee_tls_d_client_t *client,
                          uint32_t transform_handle,
                          const unsigned char *aad,
                          size_t aad_len,
                          const unsigned char *ciphertext,
                          size_t ciphertext_len,
                          unsigned char *plaintext,
                          size_t plaintext_size,
                          size_t *plaintext_len,
                          uint64_t *duration_us);

int tee_tls_d_handshake_keys(tee_tls_d_client_t *client,
                             const tee_tls_d_handshake_keys_params_t *params,
                             uint32_t *transform_handle,
                             uint64_t *duration_us);

int tee_tls_d_server_key_share(tee_tls_d_client_t *client,
                               const tee_tls_d_server_key_share_params_t *params,
                               uint64_t *duration_us);

int tee_tls_d_application_keys(tee_tls_d_client_t *client,
                               const tee_tls_d_application_keys_params_t *params,
                               uint32_t *transform_handle,
                               uint64_t *duration_us);

int tee_tls_d_finished(tee_tls_d_client_t *client,
                       const tee_tls_d_finished_params_t *params,
                       uint64_t *duration_us);

int tee_tls_d_resumption_master(tee_tls_d_client_t *client,
                                const tee_tls_d_resumption_master_params_t *params,
                                uint64_t *duration_us);

int tee_tls_d_resumption_psk(tee_tls_d_client_t *client,
                             const tee_tls_d_resumption_psk_params_t *params,
                             uint64_t *duration_us);

int tee_tls_d_get_stats(tee_tls_d_client_t *client,
                        tee_tls_d_stats_t *stats);

int tee_tls_d_reset_stats(tee_tls_d_client_t *client);

int tee_tls_d_get_last_error(tee_tls_d_client_t *client,
                             tee_tls_d_error_t *error);

#endif /* TEE_TLS_D_CLIENT_H */
