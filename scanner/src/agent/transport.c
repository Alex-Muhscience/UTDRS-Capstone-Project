#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "agent/transport.h"
#include "common/crypto.h"

#define CONNECT_TIMEOUT 5
#define BACKOFF_BASE 5
#define MAX_BACKOFF 300

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define close closesocket
#define SHUT_RDWR SD_BOTH
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#endif

// Remove the custom inet_pton implementation for Windows
// Use the system-provided InetPton instead

static int socket_connect(const char *host, int port) {
    struct addrinfo hints = {0}, *res, *p;
    int sock = -1;
    char port_str[16];
    
    snprintf(port_str, sizeof(port_str), "%d", port);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        fprintf(stderr, "Failed to resolve host: %s\n", host);
        return -1;
    }

    // Try each address until successful connection
    for (p = res; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock == -1) continue;

#ifdef _WIN32
        DWORD timeout = CONNECT_TIMEOUT * 1000;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
        struct timeval tv = {CONNECT_TIMEOUT, 0};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

        if (connect(sock, p->ai_addr, p->ai_addrlen) == 0) {
            break; // Success
        }

        close(sock);
        sock = -1;
    }

    freeaddrinfo(res);
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
#ifdef _WIN32
        Sleep(delay * 1000);
#else
        sleep(delay);
#endif
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

    // Perform TLS handshake
    int ret = SSL_connect(ssl);
    if (ret <= 0) {
        int err = SSL_get_error(ssl, ret);
        fprintf(stderr, "SSL_connect failed: %d\n", err);
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

ssize_t ssl_write_all(SSL *ssl, const void *buf, size_t len) {
    const char *ptr = buf;
    size_t remaining = len;
    
    while (remaining > 0) {
        int sent = SSL_write(ssl, ptr, (int)(remaining > INT_MAX ? INT_MAX : remaining));
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
    
    return (ssize_t)(len - remaining);
}

int verify_server_certificate(SSL *ssl, const char *host) {
    (void)host;
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

#ifdef X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS
    // Modern OpenSSL with X509_check_host
    int ret = X509_check_host(cert, host, strlen(host), X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS, NULL);
    if (ret != 1) {
        fprintf(stderr, "Hostname verification failed\n");
        X509_free(cert);
        return 0;
    }
#else
    // Fallback for older OpenSSL
    fprintf(stderr, "Warning: Using less secure hostname verification\n");
    // Implement alternative verification here if needed
#endif

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