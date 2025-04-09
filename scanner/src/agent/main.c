#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <time.h>
#include "common/crypto.h"
#include "agent/scanner.h"
#include "agent/transport.h"

// Configuration defaults
#define DEFAULT_SERVER_HOST "scanner.example.com"
#define DEFAULT_SERVER_PORT 8443
#define DEFAULT_SCAN_INTERVAL 60
#define DEFAULT_CONNECT_RETRY_DELAY 5
#define DEFAULT_MAX_RETRIES 3
#define HEARTBEAT_INTERVAL 30

// Logging macros
#ifdef _WIN32
#define log_error(fmt, ...) fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)
#define log_info(fmt, ...) fprintf(stdout, "[INFO] " fmt "\n", ##__VA_ARGS__)
#else
#include <syslog.h>
#define log_error(fmt, ...) syslog(LOG_ERR, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...) syslog(LOG_INFO, fmt, ##__VA_ARGS__)
#endif

// Configuration structure
typedef struct {
    char server_host[256];
    int server_port;
    unsigned scan_interval;
    unsigned connect_retry_delay;
    unsigned max_retries;
    char ca_cert_path[512];
    char agent_cert_path[512];
    char agent_key_path[512];
} agent_config_t;

// Cross-platform atomic running flag
#ifdef _WIN32
#include <windows.h>
volatile DWORD running = 1;
#else
#include <signal.h>
#include <stdatomic.h>
atomic_int running = 1;
#endif

/* Load configuration from file */
int load_config(const char *config_path, agent_config_t *config) {
    (void)config_path;
    // Set defaults
    strcpy(config->server_host, DEFAULT_SERVER_HOST);
    config->server_port = DEFAULT_SERVER_PORT;
    config->scan_interval = DEFAULT_SCAN_INTERVAL;
    config->connect_retry_delay = DEFAULT_CONNECT_RETRY_DELAY;
    config->max_retries = DEFAULT_MAX_RETRIES;
    strcpy(config->ca_cert_path, "configs/certs/ca.crt");
    strcpy(config->agent_cert_path, "configs/certs/agent.crt");
    strcpy(config->agent_key_path, "configs/certs/agent.key");

    // TODO: Implement actual config file parsing
    // For now we just use defaults
    return 0;
}

/* Cross-platform sleep with millisecond precision */
void platform_sleep(unsigned seconds) {
#ifdef _WIN32
    Sleep(seconds * 1000);
#else
    struct timespec ts = {seconds, 0};
    nanosleep(&ts, NULL);
#endif
}

/* Secure memory zeroing */
void secure_zero(void *s, size_t n) {
#ifdef _WIN32
    SecureZeroMemory(s, n);
#else
    volatile char *p = s;
    while (n--) *p++ = 0;
#endif
}

/* Signal/control handler setup */
#ifdef _WIN32
BOOL WINAPI console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT) {
        running = 0;
        return TRUE;
    }
    return FALSE;
}
#else
void handle_signal(int sig) {
    (void)sig;
    running = 0;
}
#endif

void setup_signal_handling(void) {
#ifdef _WIN32
    if (!SetConsoleCtrlHandler(console_handler, TRUE)) {
        log_error("Failed to set control handler");
        exit(EXIT_FAILURE);
    }
#else
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);  // Handle broken pipes
#endif
}
void cleanup_resources(SSL_CTX *ctx, SSL *ssl, scan_result_t *scan_data) {
    if (scan_data) {
        if (scan_data->networks) {
            secure_zero(scan_data->networks, 
                       sizeof(network_info_t) * scan_data->network_count);
            free(scan_data->networks);
        }
        secure_zero(scan_data, sizeof(scan_result_t));
        free(scan_data);
    }
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ctx) {
        SSL_CTX_free(ctx);
    }
}

int serialize_scan_result(scan_result_t *result, char **out_buf, size_t *out_len) {
    if (!result || !out_buf || !out_len) return -1;
    
    size_t buf_size = sizeof(system_info_t) + sizeof(size_t) + 
                     (sizeof(network_info_t) * result->network_count);
    *out_buf = malloc(buf_size);
    if (!*out_buf) return -1;
    
    char *ptr = *out_buf;
    
    // Serialize system info
    memcpy(ptr, &result->system, sizeof(system_info_t));
    ptr += sizeof(system_info_t);
    
    // Serialize network count
    memcpy(ptr, &result->network_count, sizeof(size_t));
    ptr += sizeof(size_t);
    
    // Serialize networks
    if (result->network_count > 0) {
        memcpy(ptr, result->networks, 
               sizeof(network_info_t) * result->network_count);
    }
    
    *out_len = buf_size;
    return 0;
}

int send_heartbeat(SSL *ssl) {
    const char *heartbeat_msg = "HEARTBEAT";
    size_t msg_len = strlen(heartbeat_msg);
    
    if ((size_t)ssl_write_all(ssl, heartbeat_msg, msg_len) != msg_len) {
        log_error("Heartbeat failed");
        return -1;
    }
    return 0;
}

int main(void) {
    // Initialize logging
#ifndef _WIN32
    openlog("device-scanner-agent", LOG_PID|LOG_CONS, LOG_DAEMON);
#endif

    // Load configuration
    agent_config_t config;
    if (load_config("configs/agent.conf", &config) != 0) {
        log_error("Failed to load configuration");
        return EXIT_FAILURE;
    }

    log_info("Starting device scanner agent");
    log_info("Configuration loaded - Server: %s:%d", 
             config.server_host, config.server_port);

    // Setup signal handling
    setup_signal_handling();

    // Initialize TLS context with strong crypto settings
    SSL_CTX *ctx = init_tls_client_context(
        config.ca_cert_path,
        config.agent_cert_path,
        config.agent_key_path
    );
    if (!ctx) {
        log_error("TLS initialization failed");
        return EXIT_FAILURE;
    }

    // Main loop with retry logic
    int retry_count = 0;
    time_t last_heartbeat = 0;
    time_t last_scan = 0;
    
    while (running) {
        SSL *ssl = NULL;
        scan_result_t *scan_result = NULL;
        char *serialized_data = NULL;
        size_t data_len = 0;
        time_t now = time(NULL);

        // Connect to server with retries
        for (unsigned int i = 0; i < config.max_retries; i++) {
            ssl = connect_to_server(ctx, config.server_host, config.server_port);
            if (ssl) break;
            
            if (i == config.max_retries - 1) {
                log_error("Max connection retries reached");
                goto cleanup;
            }
            
            log_info("Connection failed, retry %d/%d", i+1, config.max_retries);
            platform_sleep(config.connect_retry_delay * (i+1));  // Exponential backoff
        }

        // Verify server certificate
        if (!verify_server_certificate(ssl, config.server_host)) {
            log_error("Server certificate verification failed");
            cleanup_resources(NULL, ssl, NULL);
            continue;
        }

        // Send heartbeat if needed
        if (difftime(now, last_heartbeat) >= HEARTBEAT_INTERVAL) {
            if (send_heartbeat(ssl) != 0) {
                cleanup_resources(NULL, ssl, NULL);
                continue;
            }
            last_heartbeat = now;
            log_info("Heartbeat sent");
        }

        // Perform scan if interval has passed
        if (difftime(now, last_scan) >= config.scan_interval) {
            scan_result_t *scan_result = perform_scan();
            if (!scan_result) {
                log_error("Scan failed");
                cleanup_resources(NULL, ssl, NULL);
                platform_sleep(config.scan_interval);
                continue;
            }   
            last_scan = now;

            // Serialize scan data
            int serialize_scan_result(scan_result_t *result, char **out_buf, size_t *out_len) ;{
                log_error("Failed to serialize scan data");
                cleanup_resources(NULL, ssl, scan_result);
                continue;
            }

            // Secure data transmission
            if (ssl_write_all(ssl, serialized_data, data_len) != (ssize_t)data_len) {
                log_error("Failed to send complete scan data");
                retry_count++;
                if ((unsigned)retry_count >= config.max_retries) {
                    log_error("Max transmission retries reached");
                    running = 0;
                }
            } else {
                log_info("Scan data sent successfully");
                retry_count = 0;  // Reset on success
            }
        }

        cleanup:
        // Cleanup and wait
        if (serialized_data) {
            secure_zero(serialized_data, data_len);
            free(serialized_data);
        }
        cleanup_resources(NULL, ssl, scan_result);
        
        // Sleep but wake up for heartbeats
        time_t sleep_time = config.scan_interval;
        if (HEARTBEAT_INTERVAL < sleep_time) {
            sleep_time = HEARTBEAT_INTERVAL;
        }
        platform_sleep(sleep_time);
    }

    // Final cleanup
    cleanup_resources(ctx, NULL, NULL);
    log_info("Device scanner agent stopped");
#ifndef _WIN32
    closelog();
#endif
    return EXIT_SUCCESS;
}