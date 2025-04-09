#ifndef STORAGE_H
#define STORAGE_H

#include <openssl/ssl.h> // For SSL type

int init_storage(mongoc_client_pool_t *pool);
int store_scan_result(SSL *ssl, const char *data);
void cleanup_storage(void);

#endif // STORAGE_H