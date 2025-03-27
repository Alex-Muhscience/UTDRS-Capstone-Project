#ifndef DEVICE_SCANNER_STORAGE_H
#define DEVICE_SCANNER_STORAGE_H

#include <openssl/ssl.h>
#include "common/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file storage.h
 * @brief Storage interface for device scanner results
 */

/**
 * @brief Initialize the storage backend
 * 
 * This function must be called before any other storage operations.
 * It initializes databases, files, or other storage mechanisms.
 * 
 * @return 0 on success, -1 on failure
 * @note Thread-safe initialization is recommended
 */
int init_storage(void);

/**
 * @brief Clean up and shutdown storage backend
 * 
 * Releases all resources associated with the storage system.
 * Should be called when the application is exiting.
 */
void cleanup_storage(void);

/**
 * @brief Store device scan results
 * 
 * Persists the scan results in the configured storage backend.
 * May include client information extracted from the SSL connection.
 * 
 * @param ssl SSL connection handle (for client metadata)
 * @param data JSON formatted scan data (must be null-terminated)
 * @return 0 on success, -1 on failure
 * @warning The SSL handle must remain valid during this operation
 * @note Implementations should be thread-safe
 */
int store_scan_result(SSL *ssl, const char *data);

/**
 * @brief Retrieve stored scan results
 * 
 * @param device_id Target device identifier
 * @param[out] buffer Output buffer for JSON data
 * @param buffer_size Size of output buffer
 * @return Length of data retrieved or -1 on error
 */
int retrieve_scan_result(const char *device_id, char *buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif // DEVICE_SCANNER_STORAGE_H