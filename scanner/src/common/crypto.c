#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include "common/crypto.h"

SSL_CTX* init_tls_client_context(const char *ca_path, 
                                const char *cert_path, 
                                const char *key_path) {
    SSL_CTX *ctx = NULL;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Set minimum TLS version
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    // Load CA certificate
    if (SSL_CTX_load_verify_locations(ctx, ca_path, NULL) != 1) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    // Load client certificate
    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) != 1) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    // Load private key
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) != 1) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    // Verify private key matches certificate
    if (SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "Certificate and key don't match\n");
        goto error;
    }

    // Enable hostname verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);

    return ctx;

error:
    if (ctx) SSL_CTX_free(ctx);
    return NULL;
}