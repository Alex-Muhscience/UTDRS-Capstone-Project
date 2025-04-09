#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/err.h>

int verify_certificate(SSL *ssl) {
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) return 0;

    // Check certificate fingerprint
    unsigned char fingerprint[EVP_MAX_MD_SIZE];
    unsigned int len;
    if (!X509_digest(cert, EVP_sha256(), fingerprint, &len)) {
        X509_free(cert);
        return 0;
    }

    // Compare with known fingerprint
    const unsigned char known_fingerprint[] = {
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    if (memcmp(fingerprint, known_fingerprint, len) != 0) {
        X509_free(cert);
        return 0;
    }

    X509_free(cert);
    return 1;
}