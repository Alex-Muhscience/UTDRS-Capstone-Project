// include/agent/scanner.h
#ifndef DEVICE_SCANNER_SCANNER_H
#define DEVICE_SCANNER_SCANNER_H

#include "../common/types.h"

#ifdef __cplusplus
extern "C" {
#endif

scan_result_t* perform_scan(void);
void free_scan_result(scan_result_t *result);

#ifdef __cplusplus
}
#endif

#endif // DEVICE_SCANNER_SCANNER_H