#include "common/tls.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdlib.h>

SSL_CTX* init_tls_server_context(const char* ca_cert, const char* server_cert, const char* private_key) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Set minimum TLS version to 1.2
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    // Load certificates
    if (SSL_CTX_use_certificate_file(ctx, server_cert, SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, private_key, SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    if (!SSL_CTX_check_private_key(ctx)) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    if (ca_cert && SSL_CTX_load_verify_locations(ctx, ca_cert, NULL) <= 0) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    // Set verify options
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
    
    // Configure secure ciphers
    if (!SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384:"
                                     "ECDHE-RSA-AES256-GCM-SHA384:"
                                     "DHE-RSA-AES256-GCM-SHA384")) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    return ctx;
}