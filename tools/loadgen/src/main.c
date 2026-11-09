#include "tls_loadgen.h"

#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("tls_loadgen %s git=%s\n", TLSGEN_VERSION, TLSGEN_GIT_COMMIT);
        return EXIT_SUCCESS;
    }

    app_t app;
    if (app_initialize(&app, argc, argv) != 0) {
        app_cleanup(&app);
        return EXIT_FAILURE;
    }
    int rc = app_backend_loop(&app);
    if (rc != 0 && app.fatal_error[0] != '\0') {
        fprintf(stderr, "run failed: %s\n", app.fatal_error);
    }
    app_cleanup(&app);
    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
