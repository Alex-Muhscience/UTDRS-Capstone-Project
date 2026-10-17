#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <jansson.h>
#include <mongoc/mongoc.h>
#include <bson/bson.h>
#include <pthread.h>

// Platform-specific headers
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#define close closesocket
#define sleep(seconds) Sleep((seconds)*1000)
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <syslog.h>
#endif

#include "server/api.h"
#include "server/storage.h"
#include "common/utils.h"
#include "common/crypto.h"
#include "common/scan_message.h"

// JSON validation result codes
#define VALID_JSON_OK                0
#define VALID_JSON_TOO_LARGE         1
#define VALID_JSON_INVALID           2
#define VALID_JSON_TOO_DEEP          3
#define VALID_JSON_MISSING_FIELD     4
#define VALID_JSON_FIELD_TOO_LONG    5
#define VALID_JSON_CHECKSUM_FAIL     6

// Windows syslog replacement
#ifdef _WIN32
#define LOG_WARNING 0
#define LOG_NOTICE 0
static void win_syslog(int priority, const char *format, ...) {
    (void)priority;
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
}
#define syslog win_syslog
#endif

// Security Constants
#define MAX_CLIENTS             100
#define RATE_LIMIT_WINDOW       60          // 1 minute
#define MAX_REQUESTS_PER_MIN    30
#define MAX_JSON_DEPTH          10          // Prevent JSON bomb attacks
#define MAX_FIELD_LENGTH        256
#define CIPHER_LIST             "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
#define MONGODB_MAX_RETRIES     3           // Max retries for MongoDB operations

typedef struct {
    char ip[INET_ADDRSTRLEN];
    time_t first_request;
    time_t last_request;
    int request_count;
    bool blocked;
} client_state_t;

static client_state_t clients[MAX_CLIENTS] = {0};
static pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
static mongoc_client_pool_t *mongodb_pool = NULL;

/************************
 * DATABASE INITIALIZATION *
 ************************/

int init_mongodb_connection() {
    mongoc_init();
    
    const char *uri_str = getenv("MONGODB_URI");
    if (!uri_str) {
        syslog(LOG_WARNING, "MONGODB_URI environment variable not set");
        return -1;
    }

    bson_error_t error;
    mongoc_uri_t *uri = mongoc_uri_new_with_error(uri_str, &error);
    if (!uri) {
        syslog(LOG_WARNING, "Invalid MongoDB URI: %s", error.message);
        return -1;
    }

    mongodb_pool = mongoc_client_pool_new(uri);
    if (!mongodb_pool) {
        syslog(LOG_WARNING, "Failed to create MongoDB connection pool");
        mongoc_uri_destroy(uri);
        return -1;
    }

    mongoc_client_pool_set_error_api(mongodb_pool, 2);
    mongoc_uri_destroy(uri);

    mongoc_client_t *client = mongoc_client_pool_pop(mongodb_pool);
    if (!client) {
        syslog(LOG_WARNING, "Failed to create MongoDB client");
        return -1;
    }

    bson_t ping = BSON_INITIALIZER;
    BSON_APPEND_INT32(&ping, "ping", 1);
    
    bool ok = mongoc_client_command_simple(
        client, "admin", &ping, NULL, NULL, &error
    );
    
    bson_destroy(&ping);
    mongoc_client_pool_push(mongodb_pool, client);

    if (!ok) {
        syslog(LOG_WARNING, "MongoDB connection failed: %s", error.message);
        return -1;
    }

    syslog(LOG_NOTICE, "Connected to MongoDB Atlas");
    return 0;
}

mongoc_client_pool_t *get_mongodb_pool(void) {
    return mongodb_pool;
}

void cleanup_mongodb(void) {
    if (mongodb_pool) {
        mongoc_client_pool_destroy(mongodb_pool);
        mongodb_pool = NULL;
    }
    mongoc_cleanup();
}

/************************
 * SECURITY ENHANCEMENTS *
 ************************/

SSL_CTX* create_secure_tls_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        syslog(LOG_WARNING, "Failed to create SSL context");
        return NULL;
    }

    // Protocol constraints
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    // Cipher suite configuration
    if (SSL_CTX_set_cipher_list(ctx, CIPHER_LIST) != 1) {
        syslog(LOG_WARNING, "Failed to set cipher list");
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Enable forward secrecy
    SSL_CTX_set_ecdh_auto(ctx, 1);

    // No OCSP stapling: agents and server use certificates from the deployment's private CA
    // (scripts/generate_*.sh), which has no OCSP responder. Revocation is handled by
    // reissuing from that CA. (The previous calls set no responder callback on Windows and
    // used a BoringSSL-only function elsewhere, so they never stapled anything.)

    return ctx;
}

// Each address may make MAX_REQUESTS_PER_MIN requests per RATE_LIMIT_WINDOW; requests
// over the limit are refused until the window ends. An address that has been quiet for
// a whole window gives up its slot, so the table never fills with old addresses.
int check_client_access(const char *ip) {
    time_t now = time(NULL);
    int result = 0;

    pthread_mutex_lock(&clients_mutex);

    client_state_t *client = NULL;
    client_state_t *free_slot = NULL;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].ip[0] != '\0' && strcmp(clients[i].ip, ip) == 0) {
            client = &clients[i];
            break;
        }
        if (!free_slot &&
            (clients[i].ip[0] == '\0' || now - clients[i].last_request > RATE_LIMIT_WINDOW)) {
            free_slot = &clients[i];
        }
    }

    if (!client && free_slot) {
        client = free_slot;
        memset(client, 0, sizeof(*client));
        snprintf(client->ip, sizeof(client->ip), "%s", ip);
        client->first_request = now;
    }

    if (!client) {
        result = -1; // Every slot is in use by an active address
    } else {
        if (now - client->first_request >= RATE_LIMIT_WINDOW) {
            client->first_request = now;
            client->request_count = 0;
            client->blocked = false;
        }
        client->request_count++;
        if (client->request_count > MAX_REQUESTS_PER_MIN) {
            if (!client->blocked) {
                syslog(LOG_WARNING, "Rate limiting %s until its window ends", ip);
            }
            client->blocked = true;
            result = -1;
        }
        client->last_request = now;
    }

    pthread_mutex_unlock(&clients_mutex);
    return result;
}

/**********************
 * UTILITY FUNCTIONS *
 **********************/

int get_client_ip(SSL *ssl, char *buf, size_t len) {
    if (!ssl || !buf || len < INET_ADDRSTRLEN) {
        return -1;
    }

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    
    if (getpeername(SSL_get_fd(ssl), (struct sockaddr*)&addr, &addr_len) != 0) {
        perror("getpeername");
        return -1;
    }
    
    if (!inet_ntop(AF_INET, &addr.sin_addr, buf, len)) {
        perror("inet_ntop");
        return -1;
    }
    
    return 0;
}

// The checksum covers the other fields (see common/scan_message.h); a hash of the whole
// message could never match, because the message contains the checksum.
static bool verify_checksum(const json_t *scan, const char *checksum) {
    if (!scan || !checksum) return false;

    char expected[SCAN_CHECKSUM_HEX_LEN + 1];
    if (scan_checksum(scan, expected) != 0) return false;

    return strcmp(expected, checksum) == 0;
}

int validate_scan_json(const char *data) {
    if (!data) return VALID_JSON_INVALID;
    
    if (strlen(data) > MAX_CMD_LENGTH - 1) {
        return VALID_JSON_TOO_LARGE;
    }

    json_error_t error;
    json_t *root = json_loads(data, JSON_DECODE_ANY | JSON_REJECT_DUPLICATES, &error);
    if (!root) {
        syslog(LOG_WARNING, "Invalid JSON from client: %s (line %d)", error.text, error.line);
        return VALID_JSON_INVALID;
    }

    // Depth checking
    json_t *copy = json_deep_copy(root);
    if (!copy) {
        json_decref(root);
        return VALID_JSON_TOO_DEEP;
    }
    json_decref(copy);

    static const char *required[] = {"hostname", "os", "timestamp", "checksum", NULL};
    for (int i = 0; required[i]; i++) {
        json_t *field = json_object_get(root, required[i]);
        if (!json_is_string(field) || json_string_length(field) == 0) {
            json_decref(root);
            return VALID_JSON_MISSING_FIELD;
        }

        if (json_string_length(field) > MAX_FIELD_LENGTH) {
            json_decref(root);
            return VALID_JSON_FIELD_TOO_LONG;
        }
    }

    const char *checksum = json_string_value(json_object_get(root, "checksum"));
    if (!checksum || !verify_checksum(root, checksum)) {
        json_decref(root);
        return VALID_JSON_CHECKSUM_FAIL;
    }

    json_decref(root);
    return VALID_JSON_OK;
}

/********************
 * CORE FUNCTIONALITY *
 ********************/

void handle_client_connection(SSL *ssl) {
    if (!ssl) return;

    char client_ip[INET_ADDRSTRLEN] = {0};
    
    if (get_client_ip(ssl, client_ip, sizeof(client_ip)) != 0) {
        goto connection_error;
    }

    // Over the rate limit: close before the TLS handshake. No reply can be sent before
    // the handshake, so the agent sees the connection fail and tries again later.
    if (check_client_access(client_ip) != 0) {
        goto connection_error;
    }

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        syslog(LOG_WARNING, "TLS handshake failed from %s", client_ip);
        goto connection_error;
    }

    fd_set read_fds;
    struct timeval timeout = {30, 0}; // 30 second timeout
    char cmd[MAX_CMD_LENGTH] = {0};
    
    FD_ZERO(&read_fds);
    FD_SET(SSL_get_fd(ssl), &read_fds);
    
    if (select(SSL_get_fd(ssl)+1, &read_fds, NULL, NULL, &timeout) <= 0) {
        syslog(LOG_NOTICE, "Timeout from %s", client_ip);
        goto connection_error;
    }

    int bytes_read = SSL_read(ssl, cmd, sizeof(cmd)-1);
    if (bytes_read <= 0) {
        goto connection_error;
    }
    cmd[bytes_read] = '\0';

    process_scan_command(ssl, cmd, bytes_read);

connection_error:
    // The caller owns the connection and shuts it down (client_thread_wrapper).
    return;
}

int store_scan_with_retry(SSL *ssl, const char *scan_data) {
    if (!mongodb_pool || !ssl || !scan_data) return -1;

    mongoc_client_t *client = mongoc_client_pool_pop(mongodb_pool);
    if (!client) return -1;

    char client_ip[INET_ADDRSTRLEN] = {0};
    if (get_client_ip(ssl, client_ip, sizeof(client_ip)) != 0) {
        mongoc_client_pool_push(mongodb_pool, client);
        return -1;
    }

    // Stored as a document, not a string, so the data processor can read its fields.
    bson_error_t error;
    bson_t *scan = bson_new_from_json((const uint8_t *)scan_data, -1, &error);
    if (!scan) {
        syslog(LOG_WARNING, "Could not convert scan to BSON: %s", error.message);
        mongoc_client_pool_push(mongodb_pool, client);
        return -1;
    }

    bson_t doc;
    bson_init(&doc);
    BSON_APPEND_UTF8(&doc, "client_ip", client_ip);
    BSON_APPEND_DOCUMENT(&doc, "scan", scan);
    BSON_APPEND_DATE_TIME(&doc, "received_at", (int64_t)time(NULL) * 1000);
    BSON_APPEND_UTF8(&doc, "status", "received");
    bson_destroy(scan);

    int retries = 0;
    bool success = false;

    while (retries < MONGODB_MAX_RETRIES && !success) {
        mongoc_collection_t *collection = mongoc_client_get_collection(
            client, "utdrs_db", "scans"
        );

        success = mongoc_collection_insert_one(
            collection, &doc, NULL, NULL, &error
        );

        mongoc_collection_destroy(collection);
        
        if (!success) {
            syslog(LOG_WARNING, "MongoDB insert failed (attempt %d): %s", 
                  retries + 1, error.message);
            retries++;
#ifdef _WIN32
            Sleep(1000);
#else
            sleep(1);
#endif
        }
    }

    bson_destroy(&doc);
    mongoc_client_pool_push(mongodb_pool, client);
    return success ? 0 : -1;
}

int process_scan_command(SSL *ssl, const char *cmd, size_t cmd_len) {
    if (!ssl || !cmd) return -1;
    (void)cmd_len; // Mark cmd_len as intentionally unused

    if (strncmp(cmd, "SCAN ", 5) != 0) {
        SSL_write(ssl, "INVALID_CMD", 11);
        return -1;
    }

    const char *scan_data = cmd + 5;
    int validation_result = validate_scan_json(scan_data);

    switch (validation_result) {
        case VALID_JSON_OK:
            if (store_scan_with_retry(ssl, scan_data) == 0) {
                SSL_write(ssl, "ACK", 3);
                return 0;
            } else {
                SSL_write(ssl, "STORAGE_ERROR", 13);
                return -1;
            }
        case VALID_JSON_TOO_LARGE:
            SSL_write(ssl, "DATA_TOO_LARGE", 14);
            return -1;
        case VALID_JSON_INVALID:
            SSL_write(ssl, "INVALID_JSON", 12);
            return -1;
        default:
            SSL_write(ssl, "VALIDATION_ERROR", 16);
            return -1;
    }
}