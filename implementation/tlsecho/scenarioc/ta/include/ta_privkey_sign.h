#ifndef TA_PRIVKEY_SIGN_H
#define TA_PRIVKEY_SIGN_H

/* UUID: 2b85d8aa-7d3b-4cc3-9f6e-8f7d4a6a5c2b */
#define TA_PRIVKEY_SIGN_UUID { 0x2b85d8aa, 0x7d3b, 0x4cc3, \
    { 0x9f, 0x6e, 0x8f, 0x7d, 0x4a, 0x6a, 0x5c, 0x2b } }

#define TA_PRIVKEY_SIGN_UUID_STR "2b85d8aa-7d3b-4cc3-9f6e-8f7d4a6a5c2b"

#define TA_SIGN_CMD_IMPORT_P256_KEY  0
#define TA_SIGN_CMD_SIGN_DIGEST      1
#define TA_SIGN_CMD_GET_STATS        2
#define TA_SIGN_CMD_RESET_STATS      3

#define TEE_SIGN_P256_KEY_BLOB_LEN          96U /* d || x || y */
#define TEE_SIGN_SHA256_DIGEST_LEN          32U
#define TEE_SIGN_ECDSA_P256_RAW_SIG_LEN     64U /* r || s */

#endif /* TA_PRIVKEY_SIGN_H */
