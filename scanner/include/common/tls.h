#ifndef TLS_H
#define TLS_H

#include <openssl/ssl.h>

SSL_CTX* init_tls_server_context(const char* ca_cert, 
                                const char* server_cert, 
                                const char* private_key);

void cleanup_tls_context(SSL_CTX *ctx);

#endif /* TLS_H */