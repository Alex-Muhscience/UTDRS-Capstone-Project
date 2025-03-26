#include <string.h>
#include <openssl/crypto.h>

void secure_memzero(void *s, size_t n) {
    OPENSSL_cleanse(s, n);
}

void *secure_malloc(size_t n) {
    void *ptr = malloc(n);
    if (ptr) memset(ptr, 0, n);
    return ptr;
}

void secure_free(void **ptr, size_t n) {
    if (ptr && *ptr) {
        secure_memzero(*ptr, n);
        free(*ptr);
        *ptr = NULL;
    }
}