#ifndef DEVICE_SCANNER_TYPES_H
#define DEVICE_SCANNER_TYPES_H

#include <stdint.h>

typedef struct {
    char os_name[64];
    char os_version[64];
    uint32_t cpu_cores;
    uint64_t memory_kb;
} system_info_t;

typedef struct {
    char interface[16];
    char ip_address[16];
    uint8_t mac_address[6];
} network_info_t;

typedef struct {
    system_info_t system;
    network_info_t *networks;
    size_t network_count;
} scan_result_t;

#endif // DEVICE_SCANNER_TYPES_H