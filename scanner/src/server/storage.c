#include "server/storage.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mongoc/mongoc.h>
#include <bson/bson.h> // Include this for BCON_STRING and other BSON APIs
#include <openssl/ssl.h> // For SSL_get_fd
#include <jansson.h>
#include <ws2tcpip.h> // For InetNtop
#include "common/utils.h"

static mongoc_client_pool_t *client_pool = NULL;

int init_storage(mongoc_client_pool_t *pool) {
    if (!pool) {
        fprintf(stderr, "Invalid client pool\n");
        return -1;
    }

    client_pool = pool;

    // Test connection by popping a client from the pool
    mongoc_client_t *client = mongoc_client_pool_pop(client_pool);
    if (!client) {
        fprintf(stderr, "Failed to get client from pool\n");
        return -1;
    }

    bson_t ping = BSON_INITIALIZER;
    BSON_APPEND_INT32(&ping, "ping", 1);
    bson_error_t error;
    bool ok = mongoc_client_command_simple(
        client, "admin", &ping, NULL, NULL, &error
    );
    bson_destroy(&ping);
    mongoc_client_pool_push(client_pool, client);

    if (!ok) {
        fprintf(stderr, "MongoDB connection failed: %s\n", error.message);
        return -1;
    }

    printf("Connected to MongoDB Atlas\n");
    return 0;
}

int store_scan_result(SSL *ssl, const char *data) {
    if (!ssl || !data) {
        fprintf(stderr, "Invalid parameters\n");
        return -1;
    }

    // Validate JSON
    json_error_t error;
    json_t *root = json_loads(data, 0, &error);
    if (!root) {
        fprintf(stderr, "Invalid JSON: %s\n", error.text);
        return -1;
    }
    json_decref(root);

    // Get client IP
    char client_ip[INET_ADDRSTRLEN];
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    if (getpeername(SSL_get_fd(ssl), (struct sockaddr*)&addr, &addr_len) == -1) {
        perror("getpeername failed");
        return -1;
    }

    // Use InetNtop instead of inet_ntop
    if (!InetNtop(AF_INET, &addr.sin_addr, client_ip, sizeof(client_ip))) {
        fprintf(stderr, "Failed to convert IP address\n");
        return -1;
    }

    // Get a client from the pool
    mongoc_client_t *client = mongoc_client_pool_pop(client_pool);
    if (!client) {
        fprintf(stderr, "Failed to get client from pool\n");
        return -1;
    }

    // Create MongoDB document
    bson_t *doc = bson_new();
    BSON_APPEND_UTF8(doc, "client_ip", client_ip);
    BSON_APPEND_UTF8(doc, "data", data);
    BSON_APPEND_DATE_TIME(doc, "timestamp", (int64_t)(time(NULL)) * 1000);

    mongoc_collection_t *collection = mongoc_client_get_collection(
        client, "utdrs_db", "scans"
    );

    bson_error_t db_error;
    bool ok = mongoc_collection_insert_one(
        collection, doc, NULL, NULL, &db_error
    );

    bson_destroy(doc);
    mongoc_collection_destroy(collection);
    mongoc_client_pool_push(client_pool, client);

    if (!ok) {
        fprintf(stderr, "MongoDB insert failed: %s\n", db_error.message);
        return -1;
    }

    return 0;
}

void cleanup_storage(void) {
    if (client_pool) {
        mongoc_client_pool_destroy(client_pool);
        client_pool = NULL;
    }
}