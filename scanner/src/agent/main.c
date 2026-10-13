#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <jansson.h>
#include <time.h>
#include "common/crypto.h"
#include "common/scan_message.h"
#include "agent/scanner.h"
#include "agent/transport.h"

// Configuration defaults
#define DEFAULT_SERVER_HOST "scanner.example.com"
#define DEFAULT_SERVER_PORT 8443
#define DEFAULT_SCAN_INTERVAL 60
#define DEFAULT_CONNECT_RETRY_DELAY 5
#define DEFAULT_MAX_RETRIES 3
#define MAX_REPORTED_INTERFACES 32  // Keeps the message within the server's command limit
#define MAX_REPLY_LENGTH 64

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
    // Set defaults first
    strcpy(config->server_host, DEFAULT_SERVER_HOST);
    config->server_port = DEFAULT_SERVER_PORT;
    config->scan_interval = DEFAULT_SCAN_INTERVAL;
    config->connect_retry_delay = DEFAULT_CONNECT_RETRY_DELAY;
    config->max_retries = DEFAULT_MAX_RETRIES;
    strcpy(config->ca_cert_path, "configs/certs/ca.crt");
    strcpy(config->agent_cert_path, "configs/certs/agent.crt");
    strcpy(config->agent_key_path, "configs/certs/agent.key");

    // Try to load from config file
    FILE *file = fopen(config_path, "r");
    if (!file) {
        log_info("Config file not found, using defaults");
    } else {
        char line[512];
        while (fgets(line, sizeof(line), file)) {
            // Skip comments and empty lines
            if (line[0] == '#' || line[0] == '\n') continue;

            // Remove trailing newline
            line[strcspn(line, "\r\n")] = '\0';

            // Parse key=value pairs
            char *equals = strchr(line, '=');
            if (!equals) continue;

            *equals = '\0';
            char *key = line;
            char *value = equals + 1;

            if (strcmp(key, "server_host") == 0) {
                snprintf(config->server_host, sizeof(config->server_host), "%s", value);
            } else if (strcmp(key, "server_port") == 0) {
                config->server_port = atoi(value);
            } else if (strcmp(key, "scan_interval") == 0) {
                config->scan_interval = (unsigned)atoi(value);
            } else if (strcmp(key, "connect_retry_delay") == 0) {
                config->connect_retry_delay = (unsigned)atoi(value);
            } else if (strcmp(key, "max_retries") == 0) {
                config->max_retries = (unsigned)atoi(value);
            } else if (strcmp(key, "ca_cert_path") == 0) {
                snprintf(config->ca_cert_path, sizeof(config->ca_cert_path), "%s", value);
            } else if (strcmp(key, "agent_cert_path") == 0) {
                snprintf(config->agent_cert_path, sizeof(config->agent_cert_path), "%s", value);
            } else if (strcmp(key, "agent_key_path") == 0) {
                snprintf(config->agent_key_path, sizeof(config->agent_key_path), "%s", value);
            }
        }
        fclose(file);
    }

    // The environment overrides the file, so one image or package serves any deployment.
    const char *host = getenv("SCANNER_SERVER_HOST");
    if (host && host[0]) {
        snprintf(config->server_host, sizeof(config->server_host), "%s", host);
    }
    const char *port = getenv("SCANNER_SERVER_PORT");
    if (port && port[0]) {
        config->server_port = atoi(port);
    }

    if (config->max_retries == 0) config->max_retries = 1;
    return 0;
}

/* Cross-platform sleep that returns early when the agent is asked to stop */
void platform_sleep(unsigned seconds) {
    for (unsigned i = 0; i < seconds && running; i++) {
#ifdef _WIN32
        Sleep(1000);
#else
        struct timespec ts = {1, 0};
        nanosleep(&ts, NULL);
#endif
    }
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
    signal(SIGPIPE, SIG_IGN);  // A dropped connection is a failed write, not a reason to stop
#endif
}

/* The scan as the server's SCAN command. The caller frees the result. */
char *build_scan_message(const scan_result_t *result) {
    if (!result) return NULL;

    char timestamp[32];
    time_t now = time(NULL);
    struct tm utc;
#ifdef _WIN32
    gmtime_s(&utc, &now);
#else
    gmtime_r(&now, &utc);
#endif
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &utc);

    json_t *scan = json_object();
    json_t *interfaces = json_array();
    if (!scan || !interfaces) {
        json_decref(scan);
        json_decref(interfaces);
        return NULL;
    }

    json_object_set_new(scan, "hostname", json_string(result->system.hostname));
    json_object_set_new(scan, "os", json_string(result->system.os_name));
    json_object_set_new(scan, "os_version", json_string(result->system.os_version));
    json_object_set_new(scan, "cpu_cores", json_integer(result->system.cpu_cores));
    json_object_set_new(scan, "memory_kb", json_integer((json_int_t)result->system.memory_kb));
    json_object_set_new(scan, "timestamp", json_string(timestamp));

    static const uint8_t no_mac[6] = {0};
    for (size_t i = 0; i < result->network_count && i < MAX_REPORTED_INTERFACES; i++) {
        const network_info_t *network = &result->networks[i];
        json_t *interface = json_object();
        json_object_set_new(interface, "name", json_string(network->interface_name));
        json_object_set_new(interface, "ip", json_string(network->ip_address));
        if (memcmp(network->mac_address, no_mac, sizeof(no_mac)) != 0) {
            char mac[18];
            snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                     network->mac_address[0], network->mac_address[1], network->mac_address[2],
                     network->mac_address[3], network->mac_address[4], network->mac_address[5]);
            json_object_set_new(interface, "mac", json_string(mac));
        }
        json_array_append_new(interfaces, interface);
    }
    json_object_set_new(scan, "interfaces", interfaces);

    char checksum[SCAN_CHECKSUM_HEX_LEN + 1];
    char *body = NULL;
    if (scan_checksum(scan, checksum) == 0) {
        json_object_set_new(scan, "checksum", json_string(checksum));
        body = json_dumps(scan, JSON_COMPACT | JSON_SORT_KEYS);
    }
    json_decref(scan);
    if (!body) return NULL;

    size_t length = strlen(SCAN_COMMAND_PREFIX) + strlen(body) + 1;
    char *message = malloc(length);
    if (message) {
        snprintf(message, length, "%s%s", SCAN_COMMAND_PREFIX, body);
    }
    free(body);
    return message;
}

/* Scan this device and deliver the result. Returns 0 once the server has stored it. */
int scan_and_report(SSL_CTX *ctx, const agent_config_t *config) {
    scan_result_t *scan_result = perform_scan();
    if (!scan_result) {
        log_error("Scan failed");
        return -1;
    }

    char *message = build_scan_message(scan_result);
    free_scan_result(scan_result);
    if (!message) {
        log_error("Failed to serialize scan data");
        return -1;
    }

    // connect_to_server backs off between attempts and verifies the server's certificate.
    SSL *ssl = NULL;
    for (unsigned i = 0; i < config->max_retries && running && !ssl; i++) {
        ssl = connect_to_server(ctx, config->server_host, config->server_port);
        if (!ssl) {
            log_info("Connection failed, attempt %u/%u", i + 1, config->max_retries);
            if (i + 1 < config->max_retries) platform_sleep(config->connect_retry_delay);
        }
    }
    if (!ssl) {
        log_error("Could not connect to %s:%d", config->server_host, config->server_port);
        free(message);
        return -1;
    }

    int status = -1;
    size_t message_len = strlen(message);
    if (ssl_write_all(ssl, message, message_len) != (ssize_t)message_len) {
        log_error("Failed to send complete scan data");
    } else {
        char reply[MAX_REPLY_LENGTH] = {0};
        int received = SSL_read(ssl, reply, sizeof(reply) - 1);
        if (received > 0 && strcmp(reply, "ACK") == 0) {
            log_info("Scan delivered to %s:%d", config->server_host, config->server_port);
            status = 0;
        } else if (received > 0) {
            log_error("Server rejected the scan: %s", reply);
        } else {
            log_error("No reply from the server");
        }
    }

    disconnect(ssl);
    free(message);
    return status;
}

int main(int argc, char *argv[]) {
    // --once sends a single scan and exits with its result, for cron jobs and tests.
    int once = 0;
    const char *config_path = "configs/agent.conf";
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--once") == 0) {
            once = 1;
        } else {
            config_path = argv[i];
        }
    }

    // Initialize logging
#ifndef _WIN32
    openlog("device-scanner-agent", LOG_PID|LOG_CONS|LOG_PERROR, LOG_DAEMON);
#endif

    // Load configuration
    agent_config_t config;
    if (load_config(config_path, &config) != 0) {
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

    int status = 0;
    if (once) {
        status = scan_and_report(ctx, &config);
    } else {
        // Each scan uses its own connection: the server takes one command per connection.
        while (running) {
            scan_and_report(ctx, &config);
            platform_sleep(config.scan_interval);
        }
    }

    SSL_CTX_free(ctx);
    log_info("Device scanner agent stopped");
#ifndef _WIN32
    closelog();
#endif
    return status == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
