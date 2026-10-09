#ifndef DEVICE_SCANNER_TRANSPORT_H
#define DEVICE_SCANNER_TRANSPORT_H

#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

SSL_CTX* init_tls_client_context(const char* ca_cert, const char* cert, const char* key);
SSL* connect_to_server(SSL_CTX* ctx, const char* host, int port);
ssize_t ssl_write_all(SSL *ssl, const void *buf, size_t len);
int verify_server_certificate(SSL *ssl, const char *host);
void disconnect(SSL *ssl);

#ifdef __cplusplus
}
#endif

#endif // DEVICE_SCANNER_TRANSPORT_H