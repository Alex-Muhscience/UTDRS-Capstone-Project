#include <openssl/x509.h>

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
    const unsigned char known_fingerprint[] = {...};
    if (memcmp(fingerprint, known_fingerprint, len) != 0) {
        X509_free(cert);
        return 0;
    }

    X509_free(cert);
    return 1;
}