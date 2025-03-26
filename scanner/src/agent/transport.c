#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "agent/transport.h"
#include "common/crypto.h"

#define CONNECT_TIMEOUT 5
#define BACKOFF_BASE 5
#define MAX_BACKOFF 300

static int socket_connect(const char *host, int port) {
    struct sockaddr_in addr = {0};
    struct hostent *he;
    int sock = -1;
    struct timeval tv;
    
    // Resolve hostname
    if ((he = gethostbyname(host)) {
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    } else if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address: %s\n", host);
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    // Create socket with cloexec flag
    if ((sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)) < 0) {
        perror("socket");
        return -1;
    }

    // Set connect timeout
    tv.tv_sec = CONNECT_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // Enable TCP keepalive
    int keepalive = 1;
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));

    // Connect with timeout
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    return sock;
}

SSL* connect_to_server(SSL_CTX *ctx, const char *host, int port) {
    static int attempt = 0;
    int sock = -1;
    SSL *ssl = NULL;
    
    // Exponential backoff
    if (attempt > 0) {
        int delay = BACKOFF_BASE * (1 << (attempt-1));
        if (delay > MAX_BACKOFF) delay = MAX_BACKOFF;
        fprintf(stderr, "Connection attempt %d, waiting %d seconds...\n", attempt, delay);
        sleep(delay);
    }

    // Create TCP connection
    if ((sock = socket_connect(host, port)) < 0) {
        attempt++;
        return NULL;
    }

    // Create SSL object
    if (!(ssl = SSL_new(ctx))) {
        fprintf(stderr, "SSL_new failed\n");
        ERR_print_errors_fp(stderr);
        close(sock);
        attempt++;
        return NULL;
    }

    SSL_set_fd(ssl, sock);

    // Perform TLS handshake with timeout
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    struct timeval timeout = {CONNECT_TIMEOUT, 0};

    // Set non-blocking for handshake timeout
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    int ret = SSL_connect(ssl);
    if (ret <= 0) {
        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            if (select(sock+1, &fdset, &fdset, NULL, &timeout) <= 0) {
                fprintf(stderr, "TLS handshake timeout\n");
                goto error;
            }
            ret = SSL_connect(ssl);
        }
    }

    // Restore blocking mode
    fcntl(sock, F_SETFL, flags);

    if (ret <= 0) {
        fprintf(stderr, "SSL_connect failed: %d\n", SSL_get_error(ssl, ret));
        ERR_print_errors_fp(stderr);
        goto error;
    }

    // Verify server certificate
    if (!verify_server_certificate(ssl, host)) {
        fprintf(stderr, "Certificate verification failed\n");
        goto error;
    }

    attempt = 0; // Reset on success
    return ssl;

error:
    if (ssl) SSL_free(ssl);
    if (sock >= 0) close(sock);
    attempt++;
    return NULL;
}

int ssl_write_all(SSL *ssl, const void *buf, size_t len) {
    const char *ptr = buf;
    size_t remaining = len;
    
    while (remaining > 0) {
        int sent = SSL_write(ssl, ptr, remaining);
        if (sent <= 0) {
            int err = SSL_get_error(ssl, sent);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                continue; // Retry
            }
            return -1; // Fatal error
        }
        ptr += sent;
        remaining -= sent;
    }
    
    return 0;
}

int verify_server_certificate(SSL *ssl, const char *host) {
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        fprintf(stderr, "No server certificate\n");
        return 0;
    }

    // Basic certificate verification
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        fprintf(stderr, "Certificate verification error\n");
        X509_free(cert);
        return 0;
    }

    // Hostname verification
    int ret = X509_check_host(cert, host, strlen(host), 0, NULL);
    if (ret != 1) {
        fprintf(stderr, "Hostname verification failed\n");
        X509_free(cert);
        return 0;
    }

    // Certificate pinning (optional)
    unsigned char fingerprint[EVP_MAX_MD_SIZE];
    unsigned int len;
    if (!X509_digest(cert, EVP_sha256(), fingerprint, &len)) {
        X509_free(cert);
        return 0;
    }

    // Compare with known fingerprint
    const unsigned char known_fingerprint[] = { /* Your cert fingerprint */ };
    if (memcmp(fingerprint, known_fingerprint, len) != 0) {
        fprintf(stderr, "Certificate fingerprint mismatch\n");
        X509_free(cert);
        return 0;
    }

    X509_free(cert);
    return 1;
}

void disconnect(SSL *ssl) {
    if (ssl) {
        int sock = SSL_get_fd(ssl);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        if (sock >= 0) close(sock);
    }
}