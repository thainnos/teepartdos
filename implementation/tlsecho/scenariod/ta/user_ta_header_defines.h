#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <ta_tls_d_backend.h>

#define TA_UUID TA_TLS_D_BACKEND_UUID
#define TA_FLAGS (TA_FLAG_USER_MODE | TA_FLAG_EXEC_DDR)
#define TA_STACK_SIZE (16 * 1024)
#define TA_DATA_SIZE       (512 * 1024)
#define TA_CURRENT_TA_EXT_PROPERTIES \
    { "org.linaro.optee.examples.tls_echo.scenariod", USER_TA_PROP_TYPE_STRING, \
      "TLS Echo Scenario D lifecycle backend TA" }

#endif /* USER_TA_HEADER_DEFINES_H */
