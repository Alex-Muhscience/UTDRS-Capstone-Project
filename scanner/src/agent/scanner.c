#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "agent/scanner.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
//#pragma comment(lib, "iphlpapi.lib")
//#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#ifndef _WIN32
/* The interface's hardware address from sysfs; left as zeros when it has none. */
static void read_mac_address(const char *interface_name, uint8_t mac[6]) {
    char path[64 + MAX_INTERFACE_LEN];
    snprintf(path, sizeof(path), "/sys/class/net/%s/address", interface_name);

    FILE *file = fopen(path, "r");
    if (!file) return;

    unsigned int bytes[6];
    if (fscanf(file, "%2x:%2x:%2x:%2x:%2x:%2x",
               &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5]) == 6) {
        for (int i = 0; i < 6; i++) mac[i] = (uint8_t)bytes[i];
    }
    fclose(file);
}
#endif

scan_result_t* perform_scan() {
    scan_result_t *result = malloc(sizeof(scan_result_t));
    if (!result) return NULL;
    
    memset(result, 0, sizeof(scan_result_t));

#ifdef _WIN32
    // Windows implementation
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    DWORD hostname_len = sizeof(result->system.hostname);
    if (!GetComputerNameA(result->system.hostname, &hostname_len)) {
        result->system.hostname[0] = '\0';
    }

    // Get OS info
    OSVERSIONINFOEX osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    GetVersionEx((OSVERSIONINFO*)&osvi);
    
    snprintf(result->system.os_name, MAX_OS_LEN, "Windows %lu.%lu", 
             osvi.dwMajorVersion, osvi.dwMinorVersion);
    snprintf(result->system.os_version, MAX_OS_LEN, "Build %lu", osvi.dwBuildNumber);

    // Get memory info
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    result->system.memory_kb = memInfo.ullTotalPhys / 1024;

    // Get CPU cores (simplified for MinGW)
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    result->system.cpu_cores = sysInfo.dwNumberOfProcessors;

    // Get network interfaces
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD dwRetVal = 0;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    
    pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
    }

    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
        // Count adapters
        pAdapter = pAdapterInfo;
        while (pAdapter) {
            result->network_count++;
            pAdapter = pAdapter->Next;
        }

        // Allocate memory for interfaces
        if (result->network_count > 0) {
            result->networks = calloc(result->network_count, sizeof(network_info_t));
            if (result->networks) {
                pAdapter = pAdapterInfo;
                for (size_t i = 0; i < result->network_count && pAdapter; i++) {
                    // Replace the problematic strncpy with this safer version:
size_t copy_len = strlen(pAdapter->AdapterName);
if (copy_len >= MAX_INTERFACE_LEN) {
    copy_len = MAX_INTERFACE_LEN - 1;
}
memcpy(result->networks[i].interface_name, pAdapter->AdapterName, copy_len);
result->networks[i].interface_name[copy_len] = '\0';
                    
                    strncpy(result->networks[i].ip_address, 
                           pAdapter->IpAddressList.IpAddress.String, 
                           MAX_IP_LEN);
                    
                    memcpy(result->networks[i].mac_address,
                          pAdapter->Address,
                          sizeof(result->networks[i].mac_address));
                    
                    pAdapter = pAdapter->Next;
                }
            }
        }
    }
    
    if (pAdapterInfo) free(pAdapterInfo);
    WSACleanup();
#else
    // Linux/Unix implementation
    struct utsname os_info;
    struct sysinfo mem_info;
    struct ifaddrs *ifaddr;
    
    if (gethostname(result->system.hostname, sizeof(result->system.hostname)) != 0) {
        result->system.hostname[0] = '\0';
    }
    result->system.hostname[sizeof(result->system.hostname) - 1] = '\0';

    // Get OS info
    if (uname(&os_info) == 0) {
        // snprintf always NUL-terminates; strncpy did not when the source filled the buffer.
        snprintf(result->system.os_name, sizeof(result->system.os_name), "%s", os_info.sysname);
        snprintf(result->system.os_version, sizeof(result->system.os_version), "%s", os_info.release);
    }

    // Get memory info
    if (sysinfo(&mem_info) == 0) {
        result->system.memory_kb = mem_info.totalram / 1024;
        result->system.cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
    }

    // Get network interfaces
    if (getifaddrs(&ifaddr) == 0) {
        // First pass: count interfaces
        for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                result->network_count++;
            }
        }

        // Allocate and store interface info
        if (result->network_count > 0) {
            result->networks = calloc(result->network_count, sizeof(network_info_t));
            if (result->networks) {
                size_t idx = 0;
                for (struct ifaddrs *ifa = ifaddr; ifa != NULL && idx < result->network_count; ifa = ifa->ifa_next) {
                    if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                        snprintf(result->networks[idx].interface_name,
                                 sizeof(result->networks[idx].interface_name), "%s", ifa->ifa_name);
                        inet_ntop(AF_INET,
                                 &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr,
                                 result->networks[idx].ip_address,
                                 MAX_IP_LEN);
                        read_mac_address(result->networks[idx].interface_name,
                                         result->networks[idx].mac_address);
                        idx++;
                    }
                }
            }
        }
        freeifaddrs(ifaddr);
    }
#endif

    return result;
}

void free_scan_result(scan_result_t *result) {
    if (result) {
        if (result->networks) {
            free(result->networks);
        }
        free(result);
    }
}