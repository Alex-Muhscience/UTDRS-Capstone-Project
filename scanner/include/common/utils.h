#ifndef UTILS_H
#define UTILS_H

#include <string.h>
#include <stddef.h>

// Safe string copy function
#ifndef strcpy_s
#ifdef _WIN32
#define strcpy_s(dest, size, src) strncpy_s((dest), (size), (src), (size))
#else
static inline int strcpy_s(char *dest, size_t size, const char *src) {
    if (!dest || !src || size == 0) return -1;
    strncpy(dest, src, size);
    dest[size-1] = '\0';
    return 0;
}
#endif
#endif

#endif // UTILS_H