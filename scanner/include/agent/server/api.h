#ifndef DEVICE_SCANNER_API_H
#define DEVICE_SCANNER_API_H

#include "../../common/types.h"

#define MAX_CLIENTS 100

/**
 * @brief Handle incoming client connection
 * @param ssl SSL connection handle
 */
void handle_client_connection(SSL *ssl);

/**
 * @brief Process scan command from agent
 * @param ssl Connection handle
 * @param cmd Command string
 */
void process_scan_command(SSL *ssl, const char *cmd);

#endif // DEVICE_SCANNER_API_H