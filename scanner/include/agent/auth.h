#ifndef DEVICE_SCANNER_AUTH_H
#define DEVICE_SCANNER_AUTH_H

#include <openssl/ssl.h>

/**
 * @brief Initialize client authentication
 * @param ctx SSL context to configure
 * @return 0 on success, -1 on error
 */
int init_client_auth(SSL_CTX *ctx);

/**
 * @brief Verify server certificate
 * @param ssl Active SSL connection
 * @param host Expected hostname
 * @return 1 if valid, 0 if invalid
 */
int verify_server_certificate(SSL *ssl, const char *host);

#endif // DEVICE_SCANNER_AUTH_H