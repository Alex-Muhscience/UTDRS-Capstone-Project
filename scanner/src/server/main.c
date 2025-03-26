#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "common/crypto.h"
#include "server/storage.h"
#include "server/api.h"

#define PORT 8443
#define MAX_CONN_QUEUE 100

volatile sig_atomic_t running = 1;

void handle_signal(int sig) {
    running = 0;
}

int create_server_socket(int port) {
    int sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    // Set SO_REUSEADDR to prevent "address already in use" errors
    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

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

int main(int argc, char *argv[]) {
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
        return EXIT_FAILURE;
    }

    printf("Server started on port %d\n", PORT);

    // Main accept loop
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

        // Handle in new thread
        pthread_t thread;
        pthread_create(&thread, NULL, (void*(*)(void*))handle_client_connection, ssl);
        pthread_detach(thread);
    }

    // Cleanup
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_storage();
    return EXIT_SUCCESS;
}