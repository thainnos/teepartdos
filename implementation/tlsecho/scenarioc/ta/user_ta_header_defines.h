#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <ta_privkey_sign.h>

#define TA_UUID TA_PRIVKEY_SIGN_UUID
#define TA_FLAGS (TA_FLAG_USER_MODE | TA_FLAG_EXEC_DDR)
#define TA_STACK_SIZE (8 * 1024)
#define TA_DATA_SIZE  (64 * 1024)
#define TA_CURRENT_TA_EXT_PROPERTIES \
    { "org.linaro.optee.examples.tls_echo.scenarioc", USER_TA_PROP_TYPE_STRING, \
      "TLS Echo Scenario C private-key signing TA" }

#endif /* USER_TA_HEADER_DEFINES_H */
