#include "tls_loadgen.h"

#include <stdlib.h>

int session_pool_init(session_pool_t *pool, size_t capacity) {
    if (!pool || capacity == 0) return -1;
    pool->items = calloc(capacity, sizeof(*pool->items));
    if (!pool->items) return -1;
    pool->count = 0;
    pool->capacity = capacity;
    pool->rr_index = 0;
    return 0;
}

void session_pool_free(session_pool_t *pool) {
    if (!pool) return;
    for (size_t i = 0; i < pool->count; ++i) {
        SSL_SESSION_free(pool->items[i]);
    }
    free(pool->items);
    pool->items = NULL;
    pool->count = 0;
    pool->capacity = 0;
    pool->rr_index = 0;
}

int session_pool_push(session_pool_t *pool, SSL_SESSION *session) {
    if (!pool || !session || pool->count >= pool->capacity) return -1;
    pool->items[pool->count++] = session;
    return 0;
}

SSL_SESSION *session_pool_pop(session_pool_t *pool) {
    if (!pool || pool->count == 0) return NULL;
    SSL_SESSION *session = pool->items[--pool->count];
    pool->items[pool->count] = NULL;
    if (pool->rr_index >= pool->count && pool->count > 0) pool->rr_index %= pool->count;
    return session;
}

SSL_SESSION *session_pool_duplicate_round_robin(session_pool_t *pool) {
    if (!pool || pool->count == 0) return NULL;
    if (pool->rr_index >= pool->count) pool->rr_index = 0;
    SSL_SESSION *source = pool->items[pool->rr_index++];
    return SSL_SESSION_dup(source);
}
