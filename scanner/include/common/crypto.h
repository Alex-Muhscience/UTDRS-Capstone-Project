#ifndef DEVICE_SCANNER_CRYPTO_H
#define DEVICE_SCANNER_CRYPTO_H

#include <openssl/ssl.h>

/**
 * @brief Initialize client TLS context
 * @param ca_path Path to CA certificate
 * @param cert_path Client certificate path
 * @param key_path Client private key path
 * @return Initialized SSL_CTX or NULL on error
 */
SSL_CTX* init_tls_client_context(const char *ca_path, 
                                const char *cert_path, 
                                const char *key_path);

/**
 * @brief Initialize server TLS context
 * @param ca_path Path to CA certificate
 * @param cert_path Server certificate path
 * @param key_path Server private key path
 * @return Initialized SSL_CTX or NULL on error
 */
SSL_CTX* init_tls_server_context(const char *ca_path,
                                const char *cert_path,
                                const char *key_path);

#endif // DEVICE_SCANNER_CRYPTO_H