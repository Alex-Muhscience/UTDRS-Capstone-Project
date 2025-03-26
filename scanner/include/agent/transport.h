#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <openssl/ssl.h>

// Establishes secure connection to server
SSL* connect_to_server(SSL_CTX *ctx, const char *host, int port);

// Writes entire buffer with retry logic
int ssl_write_all(SSL *ssl, const void *buf, size_t len);

// Verifies server certificate
int verify_server_certificate(SSL *ssl, const char *host);

// Properly closes connection
void disconnect(SSL *ssl);

#endif // TRANSPORT_H