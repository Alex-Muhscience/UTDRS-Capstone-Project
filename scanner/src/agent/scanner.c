#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <ifaddrs.h>
#include "agent/scanner.h"

char* perform_scan() {
    struct utsname os_info;
    struct sysinfo mem_info;
    struct ifaddrs *ifaddr;
    
    char *result = malloc(4096);
    char *ptr = result;
    size_t remaining = 4096;

    // OS Info
    if (uname(&os_info) == 0) {
        snprintf(ptr, remaining, 
            "OS: %s %s %s\n",
            os_info.sysname, os_info.release, os_info.machine);
        advance_ptr(&ptr, &remaining);
    }

    // Memory
    if (sysinfo(&mem_info) == 0) {
        snprintf(ptr, remaining,
            "Memory: Total=%luMB Free=%luMB\n",
            mem_info.totalram / 1024 / 1024,
            mem_info.freeram / 1024 / 1024);
        advance_ptr(&ptr, &remaining);
    }

    // Network Interfaces
    if (getifaddrs(&ifaddr) == 0) {
        strncat(ptr, "Interfaces:\n", remaining);
        advance_ptr(&ptr, &remaining);
        
        for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                snprintf(ptr, remaining, "- %s\n", ifa->ifa_name);
                advance_ptr(&ptr, &remaining);
            }
        }
        freeifaddrs(ifaddr);
    }

    return result;
}