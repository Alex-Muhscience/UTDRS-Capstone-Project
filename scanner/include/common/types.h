#ifndef DEVICE_SCANNER_TYPES_H_
#define DEVICE_SCANNER_TYPES_H_

#include <stdint.h>
#include <stddef.h>

/* Maximum lengths for strings */
#define MAX_OS_LEN       64  // Sufficient for most OS names and versions
#define MAX_INTERFACE_LEN 16 // Typical length for network interface names
#define MAX_IP_LEN       46  // Enough for IPv6 addresses (e.g., "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")

/* System information structure */
struct system_info {
    char os_name[MAX_OS_LEN];       // Operating system name
    char os_version[MAX_OS_LEN];    // Operating system version
    uint32_t cpu_cores;             // Number of CPU cores
    uint64_t memory_kb;             // Total memory in kilobytes
}; // Ensure semicolon is present

/* Network interface information structure */
struct network_info {
    char interface_name[MAX_INTERFACE_LEN]; // Network interface name (e.g., "eth0")
    char ip_address[MAX_IP_LEN];       // IP address (IPv4 or IPv6)
    uint8_t mac_address[6];            // MAC address in binary format (6 bytes)
}; // Ensure semicolon is present

/* Complete scan result structure */
struct scan_result {
    struct system_info system;        // System information
    struct network_info *networks;    // Dynamically allocated array of network interfaces
    size_t network_count;             // Number of network interfaces
}; // Ensure semicolon is present

/* Typedefs for convenience */
typedef struct system_info system_info_t;
typedef struct network_info network_info_t;
typedef struct scan_result scan_result_t;

#endif // DEVICE_SCANNER_TYPES_H_