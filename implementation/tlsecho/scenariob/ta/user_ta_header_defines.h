#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <ta_key_mgmt.h>

#define TA_UUID            TA_KEY_MGMT_UUID
#define TA_FLAGS           (TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION)
#define TA_STACK_SIZE      (16 * 1024)
#define TA_DATA_SIZE       (64 * 1024)
#define TA_DESCRIPTION     "Scenario B TEE-backed session key-management TA"

#endif /* USER_TA_HEADER_DEFINES_H */
