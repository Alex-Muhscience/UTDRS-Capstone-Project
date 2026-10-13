#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include "common/scan_message.h"

int scan_checksum(const json_t *scan, char out[SCAN_CHECKSUM_HEX_LEN + 1]) {
    if (!json_is_object(scan) || !out) return -1;

    json_t *unsigned_scan = json_copy((json_t *)scan);
    if (!unsigned_scan) return -1;
    json_object_del(unsigned_scan, "checksum");

    char *canonical = json_dumps(unsigned_scan, JSON_COMPACT | JSON_SORT_KEYS);
    json_decref(unsigned_scan);
    if (!canonical) return -1;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)canonical, strlen(canonical), hash);
    free(canonical);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(out + 2 * i, 3, "%02x", hash[i]);
    }
    return 0;
}
