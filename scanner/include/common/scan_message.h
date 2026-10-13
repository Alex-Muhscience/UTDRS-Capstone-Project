#ifndef DEVICE_SCANNER_SCAN_MESSAGE_H
#define DEVICE_SCANNER_SCAN_MESSAGE_H

#include <jansson.h>

/* The wire format shared by the agent and the server: one command per connection,
 *
 *   SCAN {"hostname": ..., "os": ..., "timestamp": ..., "checksum": ...}
 *
 * The checksum is the SHA-256, in lowercase hex, of the same JSON object without its
 * "checksum" member, serialised compactly with its keys sorted. */

#define SCAN_COMMAND_PREFIX "SCAN "
#define SCAN_CHECKSUM_HEX_LEN 64

/**
 * @brief Compute the checksum of a scan message
 * @param scan The message; a "checksum" member, if present, is left out of the hash
 * @param out Receives the hex digest and a terminating NUL
 * @return 0 on success, -1 on error
 */
int scan_checksum(const json_t *scan, char out[SCAN_CHECKSUM_HEX_LEN + 1]);

#endif // DEVICE_SCANNER_SCAN_MESSAGE_H
