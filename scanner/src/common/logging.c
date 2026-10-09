#include "common/logging.h"
#include <stdlib.h>
#include <string.h>

static FILE *log_file = NULL;
static LogLevel current_log_level = LOG_LEVEL_DEBUG;

void init_logging(const char *log_file_path, LogLevel level) {
    log_file = fopen(log_file_path, "w");
    if (!log_file) {
        perror("Failed to open log file");
        exit(EXIT_FAILURE);
    }
    current_log_level = level;
}

void close_logging(void) {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}

void log_message(LogLevel level, const char *file, int line, const char *format, ...) {
    if (level < current_log_level) {
        return; // Skip logging if level is lower than current log level
    }

    // Get current time
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);

    // Format the log message
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    // Print the log message to the log file
    va_list args;
    va_start(args, format);
    fprintf(log_file, "[%s] [%s:%d] ", timestamp, file, line);
    vfprintf(log_file, format, args);
    fprintf(log_file, "\n");
    fflush(log_file); // Ensure message is written immediately
    va_end(args);
}