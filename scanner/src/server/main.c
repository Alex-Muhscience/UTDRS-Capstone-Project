#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include "common/crypto.h"
#include "server/storage.h"
#include "agent/auth.h"
#include "server/api.h"
#include "common/tls.h"  // Added for TLS functions

// Platform-specific headers
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define close closesocket
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#define PORT 8443
#define MAX_CONN_QUEUE 100
#define THREAD_STACK_SIZE (256 * 1024)  // 256KB stack size per thread

volatile sig_atomic_t running = 1;

void handle_signal(int sig) {
    (void)sig;  // Silence unused parameter warning
    running = 0;
}

int create_server_socket(int port) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return -1;
    }
#endif

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    // Set socket options
    int optval = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 
                  (const char*)&optval, sizeof(optval)) < 0) {
        perror("setsockopt");
        close(sock);
        return -1;
    }

    // Configure server address
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = INADDR_ANY
    };

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    if (listen(sock, MAX_CONN_QUEUE) < 0) {
        perror("listen");
        close(sock);
        return -1;
    }

    return sock;
}

void* client_thread_wrapper(void* arg) {
    SSL* ssl = (SSL*)arg;
    if (ssl) {
        handle_client_connection(ssl);
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    (void)argc;  // Silence unused parameter warnings
    (void)argv;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Initialize storage
    if (init_storage() != 0) {
        fprintf(stderr, "Failed to initialize storage\n");
        return EXIT_FAILURE;
    }

    // Initialize TLS context
    SSL_CTX *ctx = init_tls_server_context(
        "configs/certs/ca.crt",
        "configs/certs/server.crt",
        "configs/certs/server.key"
    );
    if (!ctx) {
        cleanup_storage();
        return EXIT_FAILURE;
    }

    // Create server socket
    int sock = create_server_socket(PORT);
    if (sock < 0) {
        SSL_CTX_free(ctx);
        cleanup_storage();
#ifdef _WIN32
        WSACleanup();
#endif
        return EXIT_FAILURE;
    }

    printf("Server started on port %d\n", PORT);

    // Main server loop
    while (running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            if (running) perror("accept");
            continue;
        }

        // Create SSL connection
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sock);

        // Create thread attributes for larger stack size
        pthread_attr_t thread_attr;
        pthread_attr_init(&thread_attr);
        pthread_attr_setstacksize(&thread_attr, THREAD_STACK_SIZE);

        // Handle client in new thread
        pthread_t thread;
        if (pthread_create(&thread, &thread_attr, client_thread_wrapper, ssl) != 0) {
            perror("pthread_create");
            SSL_free(ssl);
            close(client_sock);
        } else {
            pthread_detach(thread);
        }
        pthread_attr_destroy(&thread_attr);
    }

    // Cleanup
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_storage();
#ifdef _WIN32
    WSACleanup();
#endif
    return EXIT_SUCCESS;
}