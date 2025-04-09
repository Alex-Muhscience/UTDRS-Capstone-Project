#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <mongoc/mongoc.h>
#include "common/crypto.h"
#include "server/storage.h"
#include "agent/auth.h"
#include "server/api.h"
#include "common/tls.h"
#include "common/logging.h"

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
#include <sys/resource.h>
#endif

#define PORT 8443
#define MAX_CONN_QUEUE 100
#define THREAD_STACK_SIZE (256 * 1024)  // 256KB stack size per thread
#define MAX_THREADS 200
#define CONNECTION_TIMEOUT_SEC 30

volatile sig_atomic_t running = 1;
static mongoc_client_pool_t *mongodb_pool = NULL;
static pthread_mutex_t thread_count_mutex = PTHREAD_MUTEX_INITIALIZER;
static int active_threads = 0;

void handle_signal(int sig) {
    (void)sig;
    running = 0;
    LOG_INFO("Server shutting down gracefully...");
}

void cleanup_resources() {
    if (mongodb_pool) {
        mongoc_client_pool_destroy(mongodb_pool);
        mongoc_cleanup();
    }
#ifdef _WIN32
    WSACleanup();
#endif
}

int init_mongodb_connection() {
    mongoc_init();
    
    const char *uri_str = getenv("MONGODB_URI");
    if (!uri_str) {
        LOG_ERR("MONGODB_URI environment variable not set");
        return -1;
    }

    mongoc_uri_t *uri = mongoc_uri_new_with_error(uri_str, NULL);
    if (!uri) {
        LOG_ERR("Invalid MongoDB URI");
        return -1;
    }

    // Configure connection pool with limits
    mongoc_uri_set_option_as_int32(uri, MONGOC_URI_MAXPOOLSIZE, 100);
    mongoc_uri_set_option_as_int32(uri, MONGOC_URI_MINPOOLSIZE, 5);
    
    mongodb_pool = mongoc_client_pool_new(uri);
    mongoc_client_pool_set_error_api(mongodb_pool, 2); // Enable error API
    mongoc_uri_destroy(uri);

    // Test connection
    mongoc_client_t *client = mongoc_client_pool_pop(mongodb_pool);
    if (!client) {
        LOG_ERR("Failed to create MongoDB client");
        return -1;
    }

    bson_t *ping = BCON_NEW("ping", BCON_INT32(1));
    bson_error_t error;
    bool ok = mongoc_client_command_simple(
        client, "admin", ping, NULL, NULL, &error
    );
    bson_destroy(ping);
    mongoc_client_pool_push(mongodb_pool, client);

    if (!ok) {
        LOG_ERR("MongoDB connection failed: %s", error.message);
        return -1;
    }

    LOG_INFO("Connected to MongoDB Atlas");
    return 0;
}

int create_server_socket(int port) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        LOG_ERR("WSAStartup failed");
        return -1;
    }
#endif

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        LOG_ERR("socket creation failed: %s", strerror(errno));
        return -1;
    }

    // Set socket options
    int optval = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 
                  (const char*)&optval, sizeof(optval)) < 0) {
        LOG_ERR("setsockopt failed: %s", strerror(errno));
        close(sock);
        return -1;
    }

    // Set timeout for socket operations
    struct timeval timeout = {CONNECTION_TIMEOUT_SEC, 0};
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        LOG_WARNING("Failed to set receive timeout: %s", strerror(errno));
    }

    // Configure server address
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = INADDR_ANY
    };

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG_ERR("bind failed: %s", strerror(errno));
        close(sock);
        return -1;
    }

    if (listen(sock, MAX_CONN_QUEUE) < 0) {
        LOG_ERR("listen failed: %s", strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

void* client_thread_wrapper(void* arg) {
    SSL* ssl = (SSL*)arg;
    if (ssl) {
        // Increment active thread count
        pthread_mutex_lock(&thread_count_mutex);
        active_threads++;
        pthread_mutex_unlock(&thread_count_mutex);

        handle_client_connection(ssl);
        SSL_shutdown(ssl);
        SSL_free(ssl);

        // Decrement active thread count
        pthread_mutex_lock(&thread_count_mutex);
        active_threads--;
        pthread_mutex_unlock(&thread_count_mutex);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    // Initialize logging
    init_logging("server.log", LOG_LEVEL_DEBUG);

    // Set signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);  // Ignore broken pipe signals
#endif

    // Initialize MongoDB connection
    if (init_mongodb_connection() != 0) {
        cleanup_resources();
        return EXIT_FAILURE;
    }

    // Initialize storage with MongoDB pool
    if (init_storage(mongodb_pool) != 0) {
        LOG_ERR("Failed to initialize storage");
        cleanup_resources();
        return EXIT_FAILURE;
    }

    // Initialize TLS context
    SSL_CTX *ctx = init_tls_server_context(
        "configs/certs/ca.crt",
        "configs/certs/server.crt",
        "configs/certs/server.key"
    );
    if (!ctx) {
        LOG_ERR("Failed to initialize TLS context");
        cleanup_resources();
        return EXIT_FAILURE;
    }

    // Set TLS context options
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384");

    // Create server socket
    int sock = create_server_socket(PORT);
    if (sock < 0) {
        SSL_CTX_free(ctx);
        cleanup_resources();
        return EXIT_FAILURE;
    }

    LOG_INFO("Server started on port %d", PORT);

    // Main server loop
    while (running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            if (running) {
                LOG_WARNING("accept failed: %s", strerror(errno));
            }
            continue;
        }

        // Check thread count
        pthread_mutex_lock(&thread_count_mutex);
        if (active_threads >= MAX_THREADS) {
            pthread_mutex_unlock(&thread_count_mutex);
            LOG_WARNING("Max threads reached, rejecting connection");
            close(client_sock);
            continue;
        }
        pthread_mutex_unlock(&thread_count_mutex);

        // Create SSL connection
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sock);

        // Create thread attributes
        pthread_attr_t thread_attr;
        pthread_attr_init(&thread_attr);
        pthread_attr_setstacksize(&thread_attr, THREAD_STACK_SIZE);
        pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);

        // Handle client in new thread
        pthread_t thread;
        if (pthread_create(&thread, &thread_attr, client_thread_wrapper, ssl) != 0) {
            LOG_ERR("Failed to create thread: %s", strerror(errno));
            SSL_free(ssl);
            close(client_sock);
        }
        pthread_attr_destroy(&thread_attr);
    }

    // Cleanup
    LOG_INFO("Shutting down server...");
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_storage();
    cleanup_resources();
    close_logging();

    LOG_INFO("Server shutdown complete");
    return EXIT_SUCCESS;
}