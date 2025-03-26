#ifndef DEVICE_SCANNER_SCANNER_H
#define DEVICE_SCANNER_SCANNER_H

#include "../common/types.h"

/**
 * @brief Perform comprehensive system scan
 * @return JSON-encoded scan results (must be freed by caller)
 */
char* perform_system_scan(void);

/**
 * @brief Perform targeted network scan 
 * @param timeout_sec Maximum scan duration
 * @return Network scan results
 */
scan_result_t perform_network_scan(int timeout_sec);

/**
 * @brief Check for critical vulnerabilities
 * @param level Scan intensity (1-3)
 * @return List of detected vulnerabilities
 */
vuln_report_t check_vulnerabilities(int level);

#endif // DEVICE_SCANNER_SCANNER_H