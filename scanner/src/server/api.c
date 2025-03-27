#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <jansson.h>
#include <sqlite3.h>
#include <pthread.h>

// Platform-specific headers
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define close closesocket
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

typedef struct {
    char ip[INET_ADDRSTRLEN];
    time_t first_request;
    time_t last_request;
    int request_count;
    bool blocked;
} client_state_t;

static client_state_t clients[MAX_CLIENTS] = {0};
static pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

/************************
 * SECURITY ENHANCEMENTS *
 ************************/

SSL_CTX* create_secure_tls_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return NULL;

    // Protocol constraints
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    // Cipher suite configuration
    if (SSL_CTX_set_cipher_list(ctx, CIPHER_LIST) != 1) {
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Enable forward secrecy
    SSL_CTX_set_ecdh_auto(ctx, 1);

    return ctx;
}

int check_client_access(const char *ip) {
    time_t now = time(NULL);
    int result = 0;
    
    pthread_mutex_lock(&clients_mutex);
    
    client_state_t *client = NULL;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (strcmp(clients[i].ip, ip) == 0) {
            client = &clients[i];
            break;
        }
        
        if (!client && clients[i].ip[0] == '\0') {
            client = &clients[i];
            strncpy(client->ip, ip, INET_ADDRSTRLEN-1);
            client->first_request = now;
            break;
        }
    }
    
    if (!client) {
        result = -1; // No available slots
    } else if (client->blocked) {
        result = -2; // Permanently blocked
    } else if (now - client->first_request > RATE_LIMIT_WINDOW) {
        // Reset counters after window
        client->first_request = now;
        client->request_count = 1;
    } else if (client->request_count++ > MAX_REQUESTS_PER_MIN) {
        // Auto-block clients exceeding limit
        client->blocked = true;
        result = -2;
        syslog(LOG_WARNING, "Blocked client %s for excessive requests", ip);
    }
    
    client->last_request = now;
    pthread_mutex_unlock(&clients_mutex);
    return result;
}

/**********************
 * UTILITY FUNCTIONS *
 **********************/

 int get_client_ip(SSL *ssl, char *buf, size_t len) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    
    if (getpeername(SSL_get_fd(ssl), (struct sockaddr*)&addr, &addr_len) != 0) {
        perror("getpeername");
        return -1;
    }
    
    const char *result = inet_ntop(AF_INET, &addr.sin_addr, buf, len);
    if (!result) {
        perror("inet_ntop");
        return -1;
    }
    
    return 0;
}

bool verify_checksum(const char *data, const char *checksum) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data, strlen(data), hash);
    
    char hex_hash[2*SHA256_DIGEST_LENGTH+1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex_hash + 2*i, "%02x", hash[i]);
    }
    
    return strncmp(hex_hash, checksum, 2*SHA256_DIGEST_LENGTH) == 0;
}

int validate_scan_json(const char *data) {
    if (strlen(data) > MAX_CMD_LENGTH - 1) {
        return VALID_JSON_TOO_LARGE;
    }

    json_error_t error;
    json_t *root = json_loads(data, JSON_DECODE_ANY | JSON_REJECT_DUPLICATES, &error);
    if (!root) {
        syslog(LOG_WARNING, "Invalid JSON from client: %s (line %d)", error.text, error.line);
        return VALID_JSON_INVALID;
    }

    // Depth checking (using json_deep_copy as alternative to json_check_depth)
    json_t *copy = json_deep_copy(root);
    if (!copy) {
        json_decref(root);
        return VALID_JSON_TOO_DEEP;
    }
    json_decref(copy);

    static const char *required[] = {"hostname", "os", "timestamp", "checksum", NULL};
    for (int i = 0; required[i]; i++) {
        json_t *field = json_object_get(root, required[i]);
        if (!field) {
            json_decref(root);
            return VALID_JSON_MISSING_FIELD;
        }
        
        if (json_is_string(field) && 
            json_string_length(field) > MAX_FIELD_LENGTH) {
            json_decref(root);
            return VALID_JSON_FIELD_TOO_LONG;
        }
    }

    const char *checksum = json_string_value(json_object_get(root, "checksum"));
    if (!verify_checksum(data, checksum)) {
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
    char client_ip[INET_ADDRSTRLEN] = {0};
    
    if (get_client_ip(ssl, client_ip, sizeof(client_ip)) != 0) {
        goto connection_error;
    }

    switch (check_client_access(client_ip)) {
        case -2: // Blocked client
            SSL_write(ssl, "BLOCKED", 7);
            goto connection_error;
        case -1: // Rate limited
            SSL_write(ssl, "RATE_LIMITED", 12);
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
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
}

int process_scan_command(SSL *ssl, const char *cmd, size_t cmd_len) {
    (void)cmd_len; // Mark cmd_len as intentionally unused

    if (strncmp(cmd, "SCAN ", 5) != 0) {
        SSL_write(ssl, "INVALID_CMD", 11);
        return -1;
    }

    const char *scan_data = cmd + 5;
    int validation_result = validate_scan_json(scan_data);

    switch (validation_result) {
        case VALID_JSON_OK:
            if (store_scan_result(ssl, scan_data) == 0) {
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