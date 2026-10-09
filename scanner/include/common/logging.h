#ifndef COMMON_LOGGING_H
#define COMMON_LOGGING_H

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

// Log levels
typedef enum {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_CRITICAL
} LogLevel;

// Function prototypes
void log_message(LogLevel level, const char *file, int line, const char *format, ...);

// Macro for logging with file and line information
#define LOG(level, ...) log_message(level, __FILE__, __LINE__, __VA_ARGS__)

// Macro for specific log levels
#define LOG_DEBUG(...) LOG(LOG_LEVEL_DEBUG, __VA_ARGS__)
#define LOG_INFO(...) LOG(LOG_LEVEL_INFO, __VA_ARGS__)
#define LOG_WARNING(...) LOG(LOG_LEVEL_WARNING, __VA_ARGS__)
#define LOG_ERR(...) LOG(LOG_LEVEL_ERROR, __VA_ARGS__)
#define LOG_CRITICAL(...) LOG(LOG_LEVEL_CRITICAL, __VA_ARGS__)

// Function prototypes for initialization and cleanup
void init_logging(const char *log_file, LogLevel log_level);
void close_logging(void);

#endif // COMMON_LOGGING_H