#ifndef DEVICE_SCANNER_STORAGE_H
#define DEVICE_SCANNER_STORAGE_H

#include "../../common/types.h"

/**
 * @brief Initialize storage backend
 * @return 0 on success, -1 on failure
 */
int init_storage(void);

/**
 * @brief Store scan results
 * @param ssl Connection handle (for client info)
 * @param data Scan data in JSON format
 * @return Storage operation status
 */
int store_scan_result(SSL *ssl, const char *data);

#endif // DEVICE_SCANNER_STORAGE_H