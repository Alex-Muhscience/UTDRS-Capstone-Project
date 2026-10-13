#ifndef DEVICE_SCANNER_API_H
#define DEVICE_SCANNER_API_H

#include <mongoc/mongoc.h>

#include <openssl/ssl.h>      // For SSL type
#include <stddef.h>           // For size_t
#include <stdbool.h>          // For bool type
#include "common/types.h"     // Project-specific types

#ifdef __cplusplus
extern "C" {
#endif

// Configuration constants
#define MAX_CLIENTS 100               ///< Maximum simultaneous client connections
#define MAX_CMD_LENGTH 8192           ///< Maximum command length (a scan with its interfaces)
#define DEFAULT_TIMEOUT_MS 30000      ///< Default connection timeout in milliseconds

/**
 * @brief Initialize the API subsystem
 * @return 0 on success, -1 on failure
 * @note Must be called before any other API functions
 */
int api_init(void);

/**
 * @brief Initialize MongoDB connection
 * @return 0 on success, -1 on failure
 */
int init_mongodb_connection(void);

/**
 * @brief The MongoDB connection pool opened by init_mongodb_connection
 * @return The pool, or NULL before a successful init_mongodb_connection
 * @note The API module owns the pool; cleanup_mongodb closes it
 */
mongoc_client_pool_t *get_mongodb_pool(void);

/**
 * @brief Close the MongoDB connection pool and release the driver
 */
void cleanup_mongodb(void);

/**
 * @brief Clean up API resources
 */
void api_cleanup(void);

/**
 * @brief Handle incoming client connection
 * @param ssl SSL connection handle (must be valid)
 * @note Takes ownership of the SSL object (will free it when done)
 */
void handle_client_connection(SSL *ssl);

/**
 * @brief Process scan command from agent
 * @param ssl Established SSL connection
 * @param cmd Null-terminated command string
 * @param cmd_len Length of command (0 for auto-detection)
 * @return 0 on success, -1 on error
 */
int process_scan_command(SSL *ssl, const char *cmd, size_t cmd_len);

/**
 * @brief Send response to client
 * @param ssl SSL connection
 * @param response Response data
 * @param length Response length
 * @return Number of bytes sent or -1 on error
 */
int send_client_response(SSL *ssl, const void *response, size_t length);

/**
 * @brief Validate JSON scan data
 * @param data JSON data to validate
 * @return Validation result code (VALID_JSON_OK on success)
 */
int validate_scan_json(const char *data);

/**
 * @brief Get client IP address from SSL connection
 * @param ssl SSL connection handle
 * @param buf Buffer to store the IP address (must be at least INET_ADDRSTRLEN bytes)
 * @param len Size of the buffer
 * @return 0 on success, -1 on error
 */
int get_client_ip(SSL *ssl, char *buf, size_t len);

/**
 * @brief Check client access based on rate limiting and blocking rules
 * @param ip Client IP address
 * @return 0 if access is allowed, -1 if rate limited, -2 if blocked
 */
int check_client_access(const char *ip);

#ifdef __cplusplus
}
#endif

#endif // DEVICE_SCANNER_API_H