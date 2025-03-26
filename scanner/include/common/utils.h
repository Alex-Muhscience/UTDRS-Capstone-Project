#ifndef DEVICE_SCANNER_UTILS_H
#define DEVICE_SCANNER_UTILS_H

#include <stddef.h>

/**
 * @brief Securely zero memory
 * @param s Memory region
 * @param n Size in bytes
 */
void secure_memzero(void *s, size_t n);

/**
 * @brief Safe string copy with bounds checking
 * @param dest Destination buffer
 * @param src Source string
 * @param size Destination buffer size
 * @return 0 on success, -1 on truncation
 */
int strcpy_s(char *dest, const char *src, size_t size);

#endif // DEVICE_SCANNER_UTILS_H