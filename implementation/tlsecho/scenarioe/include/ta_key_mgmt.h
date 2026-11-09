#ifndef TA_KEY_MGMT_H
#define TA_KEY_MGMT_H

#include <stdint.h>

/* Scenario B key-management TA UUID: 159e414d-c5b1-4652-8ec0-5d42beb160a9 */
#define TA_KEY_MGMT_UUID \
    { 0x159e414d, 0xc5b1, 0x4652, \
      { 0x8e, 0xc0, 0x5d, 0x42, 0xbe, 0xb1, 0x60, 0xa9 } }

#define TA_KEY_MGMT_UUID_STR "159e414d-c5b1-4652-8ec0-5d42beb160a9"

#define TA_KM_CMD_INIT                 0U
#define TA_KM_CMD_DERIVE_SESSION_TOKEN 1U
#define TA_KM_CMD_WRAP_SESSION_STATE   2U
#define TA_KM_CMD_UNWRAP_SESSION_STATE 3U
#define TA_KM_CMD_RESET_STATS          4U
#define TA_KM_CMD_GET_STATS            5U

#define TA_KM_TOKEN_LEN                32U
#define TA_KM_MAX_PLAINTEXT_LEN        (16U * 1024U)
#define TA_KM_AES_GCM_NONCE_LEN        12U
#define TA_KM_AES_GCM_TAG_LEN          16U
#define TA_KM_BLOB_HEADER_LEN          16U
#define TA_KM_BLOB_OVERHEAD_LEN        (TA_KM_BLOB_HEADER_LEN + TA_KM_AES_GCM_NONCE_LEN + TA_KM_AES_GCM_TAG_LEN)

#endif /* TA_KEY_MGMT_H */
